from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from redis.asyncio import Redis

from app.core.dependencies import get_db, get_redis, get_current_verified_user
from app.models.user import User
from app.schemas.auth import (
    RegisterRequest,
    RegisterResponse,
    VerifyOTPRequest,
    ResendOTPRequest,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    LogoutRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ChangePasswordRequest,
    Enable2FAResponse,
    Verify2FASetupRequest,
    Verify2FALoginRequest,
    Disable2FARequest,
    TokenResponse,
)
from app.schemas.common import SuccessResponse
from app.services import auth_service
from app.services.token_service import rotate_refresh_token, logout_session

router = APIRouter()

# --- Registration ---

@router.post("/register", response_model=SuccessResponse[RegisterResponse])
async def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    result = await auth_service.register_user(
        first_name=payload.first_name,
        last_name=payload.last_name,
        password=payload.password,
        email=payload.email,
        phone_number=payload.phone_number,
        country_code=payload.country_code,
        db=db,
        redis=redis,
    )
    return SuccessResponse(
        message=result.message,
        data=result,
    )


@router.post("/verify-otp", response_model=SuccessResponse)
async def verify_otp(
    payload: VerifyOTPRequest,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await auth_service.verify_registration_otp(
        user_id=payload.user_id,
        otp_code=payload.otp_code,
        db=db,
        redis=redis,
    )
    return SuccessResponse(message="Account verified successfully")


@router.post("/resend-otp", response_model=SuccessResponse)
async def resend_otp(
    payload: ResendOTPRequest,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await auth_service.resend_registration_otp(
        user_id=payload.user_id,
        db=db,
        redis=redis,
    )
    return SuccessResponse(message="Verification code resent")


# --- Login ---

@router.post("/login", response_model=SuccessResponse[LoginResponse])
async def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    result = await auth_service.login_user(
        email=payload.email,
        phone_number=payload.phone_number,
        password=payload.password,
        device_name=request.headers.get("X-Device-Name"),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
        country=request.headers.get("X-Country-Code"),
        db=db,
        redis=redis,
    )
    return SuccessResponse(
        message="2FA verification required" if result.requires_2fa else "Login successful",
        data=result,
    )


@router.post("/verify-2fa", response_model=SuccessResponse[TokenResponse])
async def verify_2fa_login(
    payload: Verify2FALoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    tokens = await auth_service.verify_2fa_login(
        two_fa_token=payload.two_fa_token,
        totp_code=payload.totp_code,
        device_name=request.headers.get("X-Device-Name"),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
        country=request.headers.get("X-Country-Code"),
        db=db,
        redis=redis,
    )
    return SuccessResponse(message="Login successful", data=tokens)

# --- Token management ---

@router.post("/refresh", response_model=SuccessResponse[TokenResponse])
async def refresh_token(
    payload: RefreshTokenRequest,
    request: Request,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    tokens = await rotate_refresh_token(
        refresh_token=payload.refresh_token,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
        db=db,
        redis=redis,
    )
    return SuccessResponse(message="Token refreshed", data=tokens)


@router.post("/logout", response_model=SuccessResponse)
async def logout(
    payload: LogoutRequest,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await logout_session(
        refresh_token=payload.refresh_token,
        db=db,
        redis=redis,
    )
    return SuccessResponse(message="Logged out successfully")


# --- Password management ---

@router.post("/forgot-password", response_model=SuccessResponse)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await auth_service.forgot_password(
        email=payload.email,
        phone_number=payload.phone_number,
        db=db,
        redis=redis,
    )
    return SuccessResponse(
        message="If an account exists, a reset code has been sent"
    )


@router.post("/reset-password", response_model=SuccessResponse)
async def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await auth_service.reset_password(
        user_id=payload.user_id,
        otp_code=payload.otp_code,
        new_password=payload.new_password,
        db=db,
        redis=redis,
    )
    return SuccessResponse(message="Password reset successfully")


@router.put("/change-password", response_model=SuccessResponse)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    redis: Redis = Depends(get_redis),
):
    await auth_service.change_password(
        user=current_user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        db=db,
        redis=redis,
    )
    return SuccessResponse(message="Password changed successfully")

# --- 2FA management ---

@router.post("/2fa/enable", response_model=SuccessResponse[Enable2FAResponse])
async def enable_2fa(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
):
    result = await auth_service.enable_2fa(
        user=current_user,
        db=db,
    )
    return SuccessResponse(
        message="Scan the QR code with your authenticator app, then verify to complete setup",
        data=result,
    )


@router.post("/2fa/verify-enable", response_model=SuccessResponse)
async def verify_2fa_setup(
    payload: Verify2FASetupRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
):
    await auth_service.verify_2fa_setup(
        user=current_user,
        totp_code=payload.totp_code,
        db=db,
    )
    return SuccessResponse(message="Two-factor authentication enabled successfully")


@router.post("/2fa/disable", response_model=SuccessResponse)
async def disable_2fa(
    payload: Disable2FARequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
):
    await auth_service.disable_2fa(
        user=current_user,
        password=payload.password,
        totp_code=payload.totp_code,
        db=db,
    )
    return SuccessResponse(message="Two-factor authentication disabled successfully")