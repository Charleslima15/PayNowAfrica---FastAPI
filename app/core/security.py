import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from passlib.context import CryptContext
from jose import JWTError, jwt
from cryptography.fernet import Fernet
import base64
import hashlib

from app.config import get_settings

settings = get_settings()

# --- Password Hashing ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# --- JWT ---

def create_access_token(user_id: uuid.UUID, jti: str) -> str:
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        ),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: uuid.UUID, jti: str) -> str:
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        ),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        return payload
    except JWTError:
        raise ValueError("Invalid or expired token")
    
# --- Token Hashing (for refresh token storage) ---

def hash_token(raw_token: str) -> str:
    return pwd_context.hash(raw_token)


def verify_token_hash(raw_token: str, hashed_token: str) -> bool:
    return pwd_context.verify(raw_token, hashed_token)

# --- AES-256 Encryption (for KYC data) ---

def _get_fernet() -> Fernet:
    raw_key = settings.ENCRYPTION_KEY.encode()
    hashed = hashlib.sha256(raw_key).digest()
    fernet_key = base64.urlsafe_b64encode(hashed)
    return Fernet(fernet_key)


def encrypt_data(plain_text: str) -> str:
    f = _get_fernet()
    return f.encrypt(plain_text.encode()).decode()


def decrypt_data(cipher_text: str) -> str:
    f = _get_fernet()
    return f.decrypt(cipher_text.encode()).decode()