from cryptography.fernet import Fernet
from .config import settings

fernet = Fernet(settings.fernet_key.encode()) if settings.fernet_key else None

def encrypt(plaintext: str) -> bytes:
    if not fernet:
        raise RuntimeError("FERNET_KEY not configured")
    return fernet.encrypt(plaintext.encode())

def decrypt(token: bytes) -> str:
    if not fernet:
        raise RuntimeError("FERNET_KEY not configured")
    return fernet.decrypt(token).decode()