import uuid
import secrets
from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session
from redis.asyncio import Redis

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_token,
    verify_token_hash,
)
from app.core.exceptions import (
    InvalidTokenError,
    NotAuthenticatedError,
)
from app.models.session import Session as SessionModel
from app.models.user import User
from app.schemas.auth import TokenResponse
from app.config import get_settings

settings = get_settings()


# --- Redis key builders ---

def _blacklist_key(jti: str) -> str:
    return f"blacklist:{jti}"

def _2fa_pending_key(token: str) -> str:
    return f"2fa_pending:{token}"



# --- Create token pair ---

async def create_token_pair(
    user: User,
    db: Session,
    redis: Redis,
    device_name: str | None,
    ip_address: str | None,
    user_agent: str | None,
    country: str | None,
) -> TokenResponse:

    # Enforce session limit before creating a new one
    await _enforce_session_limit(user.id, db, redis)

    # Generate unique JTIs for both tokens
    access_jti = secrets.token_urlsafe(32)
    refresh_jti = secrets.token_urlsafe(32)

    # Create signed JWTs
    access_token = create_access_token(user.id, access_jti)
    refresh_token = create_refresh_token(user.id, refresh_jti)

    # Store refresh token hashed in the database
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    session = SessionModel(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh_token),
        access_token_jti=access_jti,
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        country=country,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# --- Refresh token rotation ---

async def rotate_refresh_token(
    refresh_token: str,
    db: Session,
    redis: Redis,
    ip_address: str | None,
    user_agent: str | None,
) -> TokenResponse:

    # Decode and validate the refresh token
    try:
        payload = decode_token(refresh_token)
    except ValueError:
        raise InvalidTokenError(detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise InvalidTokenError(detail="Expected refresh token")

    user_id = uuid.UUID(payload["sub"])
    old_jti = payload["jti"]

    # Find the matching session by scanning active sessions for this user
    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user_id,
            SessionModel.is_active == True,
        )
        .all()
    )

    matched_session = None
    for s in session:
        if verify_token_hash(refresh_token, s.refresh_token_hash):
            matched_session = s
            break

    if not matched_session:
        # Token not found — possible reuse attack
        # Invalidate ALL sessions for this user as a precaution
        await _invalidate_all_sessions(user_id, db, redis)
        raise InvalidTokenError(
            detail="Refresh token reuse detected. All sessions invalidated"
        )

    # Blacklist the old access token JTI
    await _blacklist_jti(redis, matched_session.access_token_jti)

    # Generate new token pair
    new_access_jti = secrets.token_urlsafe(32)
    new_refresh_jti = secrets.token_urlsafe(32)

    new_access_token = create_access_token(user_id, new_access_jti)
    new_refresh_token = create_refresh_token(user_id, new_refresh_jti)

    # Update the existing session record
    matched_session.refresh_token_hash = hash_token(new_refresh_token)
    matched_session.access_token_jti = new_access_jti
    matched_session.last_active_at = datetime.now(timezone.utc)
    matched_session.ip_address = ip_address
    matched_session.user_agent = user_agent
    matched_session.expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    db.commit()

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# --- Logout ---

async def logout_session(
    refresh_token: str,
    db: Session,
    redis: Redis,
) -> None:

    try:
        payload = decode_token(refresh_token)
    except ValueError:
        raise InvalidTokenError(detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise InvalidTokenError(detail="Expected refresh token")

    user_id = uuid.UUID(payload["sub"])

    sessions = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user_id,
            SessionModel.is_active == True,
        )
        .all()
    )

    for s in sessions:
        if verify_token_hash(refresh_token, s.refresh_token_hash):
            await _blacklist_jti(redis, s.access_token_jti)
            s.is_active = False
            db.commit()
            return

    raise InvalidTokenError(detail="Session not found or already logged out")


# --- 2FA pending token ---

async def store_2fa_pending(
    redis: Redis,
    user_id: str,
) -> str:
    """Issue a short-lived token that identifies a user mid-login pending 2FA."""
    token = secrets.token_urlsafe(32)
    key = _2fa_pending_key(token)
    await redis.setex(key, 300, user_id)  # 5 minutes
    return token


async def consume_2fa_pending(
    redis: Redis,
    two_fa_token: str,
) -> str:
    """Validate and consume the 2FA pending token. Returns user_id."""
    key = _2fa_pending_key(two_fa_token)
    user_id = await redis.get(key)

    if not user_id:
        raise InvalidTokenError(detail="2FA session expired. Please login again")

    await redis.delete(key)
    return user_id


# --- Blacklist helpers ---

async def _blacklist_jti(redis: Redis, jti: str) -> None:
    """Add a JTI to the Redis blacklist with a TTL matching access token expiry."""
    key = _blacklist_key(jti)
    ttl = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    await redis.setex(key, ttl, "1")


async def is_token_blacklisted(redis: Redis, jti: str) -> bool:
    key = _blacklist_key(jti)
    return await redis.exists(key) == 1



# --- Session helpers ---

async def _enforce_session_limit(
    user_id: uuid.UUID,
    db: Session,
    redis: Redis,
) -> None:
    """Revoke the oldest session if user is at the concurrent session limit."""
    active_sessions = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user_id,
            SessionModel.is_active == True,
        )
        .order_by(SessionModel.last_active_at.asc())
        .all()
    )

    if len(active_sessions) >= settings.MAX_CONCURRENT_SESSIONS:
        oldest = active_sessions[0]
        await _blacklist_jti(redis, oldest.access_token_jti)
        oldest.is_active = False
        db.commit()


async def _invalidate_all_sessions(
    user_id: uuid.UUID,
    db: Session,
    redis: Redis,
) -> None:
    """Revoke all active sessions for a user — used on reuse detection and password change."""
    active_sessions = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user_id,
            SessionModel.is_active == True,
        )
        .all()
    )

    for s in active_sessions:
        await _blacklist_jti(redis, s.access_token_jti)
        s.is_active = False

    db.commit()