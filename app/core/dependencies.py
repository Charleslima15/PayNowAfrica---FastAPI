from typing import AsyncGenerator
from fastapi import Depends, Header
from sqlalchemy.orm import Session
from app.db.redis import redis_client

from app.db.postgres import SessionLocal
from app.db.redis import redis_client
from app.core.exceptions import NotAuthenticatedError, InvalidTokenError
from app.core.security import decode_token
from app.config import get_settings

from app.models.user import User
from sqlalchemy.orm import Session as DBSession
import uuid

settings = get_settings()

# --- Database session ---

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Redis ---

async def get_redis():
    return redis_client

# --- Token extraction ---

def get_token_from_header(authorization: str = Header(...)) -> str:
    if not authorization.startswith("Bearer "):
        raise NotAuthenticatedError(detail="Invalid authorization header format")
    return authorization.split(" ", 1)[1]


# --- Current user extraction ---

async def get_current_user(
    token: str = Depends(get_token_from_header),
    db: DBSession = Depends(get_db),
) -> User:
    from app.services.token_service import is_token_blacklisted

    try:
        payload = decode_token(token)
    except ValueError:
        raise InvalidTokenError()

    if payload.get("type") != "access":
        raise InvalidTokenError(detail="Expected access token")

    jti = payload.get("jti")
    if not jti:
        raise InvalidTokenError()

    blacklisted = await is_token_blacklisted(redis_client, jti)
    if blacklisted:
        raise NotAuthenticatedError(detail="Token has been revoked")

    user_id = payload.get("sub")
    if not user_id:
        raise InvalidTokenError()

    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise InvalidTokenError()

    return user

def get_current_verified_user(
    current_user: User = Depends(get_current_user),
) -> User:
    from app.core.exceptions import AccountNotVerifiedError, AccountLockedError, AccountDisabledError

    if not current_user.is_active:
        raise AccountDisabledError()
    if current_user.is_locked:
        raise AccountLockedError()
    if not current_user.is_verified:
        raise AccountNotVerifiedError()

    return current_user


def get_admin_user(
    current_user: User = Depends(get_current_verified_user),
) -> User:
    from app.core.exceptions import PermissionDeniedError
    if not current_user.is_admin:
        raise PermissionDeniedError()
    return current_user