import asyncio
import logging
import os
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exception_handlers import http_exception_handler as fastapi_http_exception_handler
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .db import SessionLocal, init_db
from .models import Secret
from .crypto import encrypt, decrypt
from .auth import oauth, get_session, set_session, clear_session

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


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_PURGE_INTERVAL_SECONDS = 3600
PURGE_INTERVAL_SECONDS = getattr(settings, "purge_interval_seconds", DEFAULT_PURGE_INTERVAL_SECONDS)
if PURGE_INTERVAL_SECONDS <= 0:
    PURGE_INTERVAL_SECONDS = DEFAULT_PURGE_INTERVAL_SECONDS
_purge_task: asyncio.Task | None = None


def purge_expired_once() -> int:
    with SessionLocal() as db:
        try:
            deleted = Secret.purge_expired(db)
            db.commit()
            return deleted
        except Exception:
            db.rollback()
            raise


async def _purge_expired_secrets_periodically():
    while True:
        try:
            deleted = await asyncio.to_thread(purge_expired_once)
            if deleted:
                logger.info("Purged %d expired secrets", deleted)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Failed to purge expired secrets")
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)


@app.on_event("startup")
async def start_background_tasks():
    global _purge_task
    try:
        await asyncio.to_thread(purge_expired_once)
    except Exception:
        logger.exception("Failed to purge expired secrets on startup")
    if _purge_task is None or _purge_task.done():
        _purge_task = asyncio.create_task(_purge_expired_secrets_periodically())


@app.on_event("shutdown")
async def stop_background_tasks():
    global _purge_task
    if _purge_task:
        _purge_task.cancel()
        try:
            await _purge_task
        except asyncio.CancelledError:
            pass
        _purge_task = None


@app.exception_handler(HTTPException)
async def styled_http_exception_handler(request: Request, exc: HTTPException):
    accept_header = request.headers.get("accept", "").lower()
    wants_json = "application/json" in accept_header
    wants_html = "text/html" in accept_header

    if exc.status_code == 403 and wants_html and not wants_json:
        session = await get_session(request)
        user = session.get("user")
        return templates.TemplateResponse(
            "forbidden.html",
            {
                "request": request,
                "user": user,
                "detail": exc.detail,
            },
            status_code=exc.status_code,
        )

    return await fastapi_http_exception_handler(request, exc)

# --- DB dependency

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Simple pages (minimal UI)

@app.get("/")
async def home(request: Request):
    session = await get_session(request)
    user = session.get("user")
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "user": user,
        },
    )

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

    # SQLite may return naive datetimes; treat them as UTC
    expires_at = s.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    share_url = f"{settings.base_url}/s/{token}"
    response_payload = {
        'id': str(s.id),
        'title': s.title,
        'share_url': share_url,
        'expires_at': expires_at,
    }

    accept_header = request.headers.get('accept', '').lower()
    if 'application/json' in accept_header:
        json_payload = response_payload.copy()
        json_payload['expires_at'] = s.expires_at.isoformat()
        return JSONResponse(json_payload)

    return templates.TemplateResponse(
        "secret_created.html",
        {
            "request": request,
            "user": user,
            "secret": response_payload,
        },
        status_code=201,
    )

# --- API/Page: view secret by token

@app.get('/s/{token}')
async def view_secret(token: str, request: Request, db: Session = Depends(get_db)):
    session = await get_session(request)
    user = session.get('user')
    if not user:
        return RedirectResponse(url='/login')

    s: Secret | None = db.query(Secret).filter(Secret.token == token).first()

    # SQLite may return naive datetimes; treat them as UTC
    expires_at = s.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not s or s.revoked:
        raise HTTPException(status_code=404, detail='Not found')
    if datetime.now(timezone.utc) >= expires_at.astimezone(timezone.utc):
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
    secret_context = {
        'title': s.title or 'Secret',
        'content': plaintext,
        'expires_at': expires_at,
        'creator': s.creator,
    }

    return templates.TemplateResponse(
        "view_secret.html",
        {
            "request": request,
            "user": user,
            "secret": secret_context,
        },
    )

# --- Health
@app.get('/healthz')
async def health():
    return PlainTextResponse('ok')
