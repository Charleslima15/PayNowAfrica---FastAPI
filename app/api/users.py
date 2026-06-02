from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from redis.asyncio import Redis

from app.core.dependencies import get_db, get_redis, get_current_verified_user
from app.models.user import User
from app.schemas.user import UserProfileResponse, UpdateProfileRequest, SessionResponse
from app.schemas.common import SuccessResponse
from app.services import session_service
from app.core.security import decode_token
from app.core.dependencies import get_token_from_header

router = APIRouter()


# --- Profile ---

@router.get("/me", response_model=SuccessResponse[UserProfileResponse])
async def get_profile(
    current_user: User = Depends(get_current_verified_user),
):
    return SuccessResponse(
        message="Profile retrieved successfully",
        data=UserProfileResponse(
            user_id=str(current_user.id),
            first_name=current_user.first_name,
            last_name=current_user.last_name,
            email=current_user.email,
            phone_number=current_user.phone_number,
            country_code=current_user.country_code,
            is_verified=current_user.is_verified,
            is_2fa_enabled=current_user.is_2fa_enabled,
            kyc_level=current_user.kyc_level.value,
            created_at=current_user.created_at,
            last_login_at=current_user.last_login_at,
        ),
    )


@router.put("/me", response_model=SuccessResponse[UserProfileResponse])
async def update_profile(
    payload: UpdateProfileRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
):
    from app.models.user import VerificationLevel

    # Lock profile updates after KYC verification
    if current_user.kyc_level != VerificationLevel.LEVEL_0:
        from app.core.exceptions import PermissionDeniedError
        raise PermissionDeniedError(
            detail="Profile updates are locked after KYC verification"
        )

    if payload.first_name is not None:
        current_user.first_name = payload.first_name.strip()
    if payload.last_name is not None:
        current_user.last_name = payload.last_name.strip()
    if payload.country_code is not None:
        current_user.country_code = payload.country_code

    db.commit()
    db.refresh(current_user)

    return SuccessResponse(
        message="Profile updated successfully",
        data=UserProfileResponse(
            user_id=str(current_user.id),
            first_name=current_user.first_name,
            last_name=current_user.last_name,
            email=current_user.email,
            phone_number=current_user.phone_number,
            country_code=current_user.country_code,
            is_verified=current_user.is_verified,
            is_2fa_enabled=current_user.is_2fa_enabled,
            kyc_level=current_user.kyc_level.value,
            created_at=current_user.created_at,
            last_login_at=current_user.last_login_at,
        ),
    )


# --- Sessions ---

@router.get("/me/sessions", response_model=SuccessResponse[list[SessionResponse]])
async def get_sessions(
    current_user: User = Depends(get_current_verified_user),
    token: str = Depends(get_token_from_header),
    db: Session = Depends(get_db),
):
    payload = decode_token(token)
    current_jti = payload.get("jti", "")

    sessions = await session_service.get_active_sessions(
        user=current_user,
        db=db,
        current_access_jti=current_jti,
    )

    return SuccessResponse(
        message="Sessions retrieved successfully",
        data=sessions,
    )


@router.delete(
    "/me/sessions/{session_id}",
    response_model=SuccessResponse,
)
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await session_service.revoke_session(
        user=current_user,
        session_id=session_id,
        db=db,
        redis=redis,
    )
    return SuccessResponse(message="Session revoked successfully")