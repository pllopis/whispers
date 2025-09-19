import os
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .db import SessionLocal, init_db
from .models import Secret
from .crypto import encrypt, decrypt
from .auth import oauth, get_session, set_session, clear_session, SESSION_COOKIE

# Initialize
init_db()
app = FastAPI(title="Whispers")
# Starlette session middleware is required by Authlib to store state/nonce
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site="lax",
)
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# --- DB dependency

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Simple pages (minimal UI)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session = await get_session(request)
    user = session.get("user")
    return HTMLResponse(f"""
        <html><body style='font-family:sans-serif'>
        <h2>Whispers</h2>
        <p>Logged in as: <b>{user.get('preferred_username') if user else 'anonymous'}</b></p>
        <ul>
          <li><a href='/login'>Login</a> | <a href='/logout'>Logout</a></li>
        </ul>
        <h3>Create a secret</h3>
        <form method='post' action='/api/secrets'>
          <label>Title (optional)</label><br/><input name='title' style='width:360px' /><br/>
          <label>Secret text</label><br/><textarea name='content' rows=6 cols=60 required></textarea><br/>
          <label>Expires in (hours)</label><br/><input type='number' name='expires_in_hours' value='24' min='1'/><br/>
          <label>Allowed users (comma separated usernames)</label><br/><input name='allowed_users' style='width:360px' /><br/>
          <label>Allowed groups (comma separated group names)</label><br/><input name='allowed_groups' style='width:360px' /><br/>
          <button type='submit'>Create</button>
        </form>
        </body></html>
    """)

# --- OIDC routes

@app.get('/login')
async def login(request: Request):
    redirect_uri = settings.oidc_redirect_uri
    return await oauth.oidc.authorize_redirect(request, redirect_uri)

@app.get('/callback')
async def auth_callback(request: Request):
    token = await oauth.oidc.authorize_access_token(request)
    userinfo = token.get('userinfo')
    if not userinfo:
        # Fallback to userinfo endpoint
        userinfo = await oauth.oidc.userinfo(token=token)
    # Save small subset in session cookie
    user = {
        'sub': userinfo.get('sub'),
        'email': userinfo.get('email'),
        'preferred_username': userinfo.get('preferred_username') or userinfo.get('email') or userinfo.get('sub'),
        settings.groups_claim: userinfo.get(settings.groups_claim, []),
    }
    resp = RedirectResponse(url='/')
    await set_session(resp, { 'user': user })
    return resp

@app.get('/logout')
async def logout(request: Request):
    resp = RedirectResponse(url='/')
    await clear_session(resp)
    return resp

# --- Helpers

def current_user_or_401(session: dict) -> dict:
    user = session.get('user')
    if not user:
        raise HTTPException(status_code=401, detail='Not authenticated')
    return user

# --- API: create secret

@app.post('/api/secrets')
async def create_secret(
    request: Request,
    title: Optional[str] = Form(None),
    content: str = Form(...),
    expires_in_hours: int = Form(24),
    allowed_users: Optional[str] = Form(""),
    allowed_groups: Optional[str] = Form(""),
    db: Session = Depends(get_db),
):
    session = await get_session(request)
    user = current_user_or_401(session)

    token = pysecrets.token_urlsafe(24)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
    ciphertext = encrypt(content)

    s = Secret(
        token=token,
        title=title,
        ciphertext=ciphertext,
        creator=user.get('preferred_username') or user.get('sub'),
        allowed_users=",".join([u.strip() for u in (allowed_users or "").split(',') if u.strip()]) or None,
        allowed_groups=",".join([g.strip() for g in (allowed_groups or "").split(',') if g.strip()]) or None,
        expires_at=expires_at,
    )
    db.add(s)
    db.commit()

    share_url = f"{settings.base_url}/s/{token}"
    return JSONResponse({
        'id': str(s.id),
        'title': s.title,
        'share_url': share_url,
        'expires_at': s.expires_at.isoformat(),
    })

# --- API/Page: view secret by token

@app.get('/s/{token}')
async def view_secret(token: str, request: Request, db: Session = Depends(get_db)):
    session = await get_session(request)
    user = session.get('user')
    if not user:
        return RedirectResponse(url='/login')

    s: Secret | None = db.query(Secret).filter(Secret.token == token).first()
    if not s or s.revoked:
        raise HTTPException(status_code=404, detail='Not found')
    if s.is_expired():
        raise HTTPException(status_code=410, detail='Expired')

    username = user.get('preferred_username') or user.get('email') or user.get('sub')
    groups = set(user.get(settings.groups_claim) or [])

    # Authorization check
    allowed_users = set((s.allowed_users or "").split(',')) - {''}
    allowed_groups = set((s.allowed_groups or "").split(',')) - {''}

    authorized = False
    if allowed_users:
        authorized = username in allowed_users
    if not authorized and allowed_groups:
        authorized = len(groups.intersection(allowed_groups)) > 0
    if not allowed_users and not allowed_groups:
        authorized = True  # if none provided, treat as open to any authenticated user

    if not authorized:
        raise HTTPException(status_code=403, detail='Forbidden')

    plaintext = decrypt(s.ciphertext)
    # Basic HTML rendering for convenience
    return HTMLResponse(f"""
        <html><body style='font-family:sans-serif'>
        <h3>{(s.title or 'Secret')}</h3>
        <pre style='white-space:pre-wrap;background:#f6f8fa;padding:12px;border-radius:8px'>{plaintext}</pre>
        <p>Expires at: {s.expires_at.isoformat()}</p>
        </body></html>
    """)

# --- Health
@app.get('/healthz')
async def health():
    return PlainTextResponse('ok')