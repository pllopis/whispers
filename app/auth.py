from starlette.requests import Request
from starlette.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from itsdangerous import URLSafeSerializer
from .config import settings

serializer = URLSafeSerializer(settings.session_secret, salt="session")

oauth = OAuth()
oauth.register(
    name="oidc",
    server_metadata_url=f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration",
    client_id=settings.oidc_client_id,
    client_secret=settings.oidc_client_secret,
    client_kwargs={"scope": settings.oidc_scopes},
)

SESSION_COOKIE = "ss_session"

async def get_session(request: Request) -> dict:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return {}
    try:
        return serializer.loads(raw)
    except Exception:
        return {}

async def set_session(response: RedirectResponse, data: dict):
    response.set_cookie(SESSION_COOKIE, serializer.dumps(data), httponly=True, samesite="lax")

async def clear_session(response: RedirectResponse):
    response.delete_cookie(SESSION_COOKIE)

async def require_login(request: Request):
    session = await get_session(request)
    if session.get("user"):
        return session
    # save where to go back to
    request.session["post_login_redirect"] = str(request.url)
    return RedirectResponse(url="/login")