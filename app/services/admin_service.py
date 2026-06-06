import uuid
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as SessionModel
from app.models.kyc import KYCRecord
from app.core.exceptions import UserNotFoundError
from app.config import get_settings

settings = get_settings()

def get_users(
    db: Session,
    page: int = 1,
    limit: int = 20,
) -> dict:
    offset = (page - 1) * limit

    total = db.query(User).count()
    users = (
        db.query(User)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "users": users,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
    }

def get_user_detail(
    user_id: str,
    db: Session,
) -> dict:

    user = db.query(User).filter(
        User.id == uuid.UUID(user_id)
    ).first()

    if not user:
        raise UserNotFoundError()

    active_sessions = db.query(SessionModel).filter(
        SessionModel.user_id == user.id,
        SessionModel.is_active == True,
    ).count()

    kyc_record = (
        db.query(KYCRecord)
        .filter(KYCRecord.user_id == user.id)
        .order_by(KYCRecord.created_at.desc())
        .first()
    )

    return {
        "user": user,
        "active_sessions": active_sessions,
        "kyc_record": kyc_record,
    }

def unlock_user(
    user_id: str,
    db: Session,
) -> User:

    user = db.query(User).filter(
        User.id == uuid.UUID(user_id)
    ).first()

    if not user:
        raise UserNotFoundError()

    user.is_locked = False
    user.failed_login_attempts = 0
    user.locked_at = None
    db.commit()
    db.refresh(user)

    return user