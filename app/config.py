import os
from pydantic import BaseModel

class Settings(BaseModel):
    oidc_issuer: str = os.getenv("OIDC_ISSUER", "https://ska-iam.stfc.ac.uk/")
    oidc_client_id: str = os.getenv("OIDC_CLIENT_ID", "")
    oidc_client_secret: str = os.getenv("OIDC_CLIENT_SECRET", "")
    oidc_redirect_uri: str = os.getenv("OIDC_REDIRECT_URI", "http://localhost:8080/callback")
    oidc_scopes: str = os.getenv("OIDC_SCOPES", "openid profile email groups")
    groups_claim: str = os.getenv("GROUPS_CLAIM", "groups")

    session_secret: str = os.getenv("SESSION_SECRET", "change-me-session-secret")
    fernet_key: str = os.getenv("FERNET_KEY", "")

    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
    base_url: str = os.getenv("BASE_URL", "http://localhost:8080")

    purge_interval_seconds: int = int(os.getenv("PURGE_INTERVAL_SECONDS", "3600"))

settings = Settings()
