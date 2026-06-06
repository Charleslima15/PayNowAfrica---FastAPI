from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.dependencies import get_db, get_admin_user
from app.models.user import User
from app.schemas.common import SuccessResponse
from app.services import admin_service

router = APIRouter()

@router.get("/users", response_model=SuccessResponse)
def list_users(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    result = admin_service.get_users(db=db, page=page, limit=limit)

    return SuccessResponse(
        message="Users retrieved successfully",
        data={
            "users": [
                {
                    "user_id": str(u.id),
                    "first_name": u.first_name,
                    "last_name": u.last_name,
                    "email": u.email,
                    "phone_number": u.phone_number,
                    "is_verified": u.is_verified,
                    "is_locked": u.is_locked,
                    "is_active": u.is_active,
                    "kyc_level": u.kyc_level.value,
                    "created_at": str(u.created_at),
                }
                for u in result["users"]
            ],
            "total": result["total"],
            "page": result["page"],
            "pages": result["pages"],
        },
    )

@router.get("/users/{user_id}", response_model=SuccessResponse)
def get_user(
    user_id: str,
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    result = admin_service.get_user_detail(user_id=user_id, db=db)
    user = result["user"]
    kyc = result["kyc_record"]

    return SuccessResponse(
        message="User retrieved successfully",
        data={
            "user_id": str(user.id),
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "phone_number": user.phone_number,
            "is_verified": user.is_verified,
            "is_locked": user.is_locked,
            "is_active": user.is_active,
            "is_2fa_enabled": user.is_2fa_enabled,
            "kyc_level": user.kyc_level.value,
            "failed_login_attempts": user.failed_login_attempts,
            "created_at": str(user.created_at),
            "last_login_at": str(user.last_login_at) if user.last_login_at else None,
            "active_sessions": result["active_sessions"],
            "kyc": {
                "status": kyc.status.value,
                "id_type": kyc.id_type.value,
                "verified_at": str(kyc.verified_at) if kyc.verified_at else None,
                "failure_reason": kyc.failure_reason,
            } if kyc else None,
        },
    )

@router.put("/users/{user_id}/unlock", response_model=SuccessResponse)
def unlock_user(
    user_id: str,
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    user = admin_service.unlock_user(user_id=user_id, db=db)

    return SuccessResponse(
        message=f"Account for {user.first_name} {user.last_name} unlocked successfully",
    )