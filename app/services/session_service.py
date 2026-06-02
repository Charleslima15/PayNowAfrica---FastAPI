import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session
from redis.asyncio import Redis

from app.models.session import Session as SessionModel
from app.models.user import User
from app.schemas.user import SessionResponse
from app.services.token_service import _blacklist_jti
from app.core.exceptions import SessionNotFoundError, PermissionDeniedError
from app.config import get_settings

settings = get_settings()

async def get_active_sessions(
    user: User,
    db: Session,
    current_access_jti: str,
) -> list[SessionResponse]:

    sessions = (
        db.query(SessionModel)
        .filter(
            SessionModel.user_id == user.id,
            SessionModel.is_active == True,
        )
        .order_by(SessionModel.last_active_at.desc())
        .all()
    )

    result = []
    for s in sessions:
        # Check inactivity timeout
        inactivity_limit = timedelta(
            minutes=settings.SESSION_INACTIVITY_TIMEOUT_MINUTES
        )
        if datetime.now(timezone.utc) - s.last_active_at > inactivity_limit:
            s.is_active = False
            db.commit()
            continue

        result.append(SessionResponse(
            session_id=str(s.id),
            device_name=s.device_name,
            ip_address=s.ip_address,
            country=s.country,
            created_at=s.created_at,
            last_active_at=s.last_active_at,
            is_current=s.access_token_jti == current_access_jti,
        ))

    return result

async def revoke_session(
    user: User,
    session_id: str,
    db: Session,
    redis: Redis,
) -> None:

    session = db.query(SessionModel).filter(
        SessionModel.id == uuid.UUID(session_id),
    ).first()

    if not session:
        raise SessionNotFoundError()

    # Users can only revoke their own sessions
    if session.user_id != user.id:
        raise PermissionDeniedError()

    if not session.is_active:
        raise SessionNotFoundError(detail="Session is already inactive")

    await _blacklist_jti(redis, session.access_token_jti)
    session.is_active = False
    db.commit()


async def update_session_activity(
    db: Session,
    access_jti: str,
) -> None:
    """Refresh last_active_at on every authenticated request."""
    session = db.query(SessionModel).filter(
        SessionModel.access_token_jti == access_jti,
    ).first()

    if session and session.is_active:
        session.last_active_at = datetime.now(timezone.utc)
        db.commit()