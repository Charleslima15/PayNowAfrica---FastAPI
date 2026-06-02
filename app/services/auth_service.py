import uuid
import pyotp
import qrcode
import qrcode.image.svg
import io
import base64
import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from redis.asyncio import Redis

from app.models.user import User, AuthProvider, VerificationLevel
from app.models.otp import OTPRecord, OTPPurpose
from app.core.security import (
    hash_password,
    verify_password,
    encrypt_data,
)
from app.core.exceptions import (
    EmailAlreadyExistsError,
    PhoneAlreadyExistsError,
    InvalidCredentialsError,
    AccountLockedError,
    AccountNotVerifiedError,
    AccountDisabledError,
    TwoFactorRequiredError,
    TwoFactorAlreadyEnabledError,
    RateLimitExceededError,
    PasswordMismatchError,
    UserNotFoundError,
    InvalidTokenError,
)
from app.services.otp_service import (
    store_otp,
    verify_otp,
    check_resend_limit,
    increment_resend_counter,
    invalidate_otp,
)
from app.services.token_service import (
    create_token_pair,
    store_2fa_pending,
    consume_2fa_pending,
    _invalidate_all_sessions,
)
from app.schemas.auth import (
    RegisterResponse,
    LoginResponse,
    TokenResponse,
    Enable2FAResponse,
)
from app.utils.validators import normalize_email, normalize_phone
from app.config import get_settings

settings = get_settings()

# --- Registration ---

async def register_user(
    first_name: str,
    last_name: str,
    password: str,
    db: Session,
    redis: Redis,
    email: str | None = None,
    phone_number: str | None = None,
    country_code: str | None = None,
) -> RegisterResponse:

    # Normalize inputs
    if email:
        email = normalize_email(email)
    if phone_number:
        phone_number = normalize_phone(phone_number)

    # Check for duplicates
    if email:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            raise EmailAlreadyExistsError()

    if phone_number:
        existing = db.query(User).filter(
            User.phone_number == phone_number
        ).first()
        if existing:
            raise PhoneAlreadyExistsError()

    # Determine auth provider
    auth_provider = AuthProvider.EMAIL if email else AuthProvider.PHONE

    # Create user — unverified until OTP confirmed
    user = User(
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        email=email,
        phone_number=phone_number,
        hashed_password=hash_password(password),
        auth_provider=auth_provider,
        country_code=country_code,
        is_verified=False,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Determine OTP purpose and TTL
    if auth_provider == AuthProvider.EMAIL:
        purpose = OTPPurpose.EMAIL_VERIFICATION.value
        ttl = settings.OTP_EXPIRE_MINUTES_EMAIL
    else:
        purpose = OTPPurpose.PHONE_VERIFICATION.value
        ttl = settings.OTP_EXPIRE_MINUTES_SMS

    # Generate and store OTP in Redis
    otp_code = await store_otp(
        redis=redis,
        user_id=str(user.id),
        purpose=purpose,
        ttl_minutes=ttl,
    )

    # Send OTP — placeholder until email/SMS services are built
    print(f"[DEV] OTP for {email or phone_number}: {otp_code}")

    return RegisterResponse(
        user_id=str(user.id),
        message=f"Account created. Verification code sent to "
                f"{'email' if auth_provider == AuthProvider.EMAIL else 'phone number'}",
        auth_provider=auth_provider.value,
    )

# --- OTP Verification ---

async def verify_registration_otp(
    user_id: str,
    otp_code: str,
    db: Session,
    redis: Redis,
) -> bool:

    user = db.query(User).filter(
        User.id == uuid.UUID(user_id)
    ).first()
    if not user:
        raise UserNotFoundError()

    purpose = (
        OTPPurpose.EMAIL_VERIFICATION.value
        if user.auth_provider == AuthProvider.EMAIL
        else OTPPurpose.PHONE_VERIFICATION.value
    )

    await verify_otp(
        redis=redis,
        user_id=user_id,
        purpose=purpose,
        submitted_code=otp_code,
    )

    # Mark user as verified
    user.is_verified = True
    db.commit()

    return True


async def resend_registration_otp(
    user_id: str,
    db: Session,
    redis: Redis,
) -> None:

    user = db.query(User).filter(
        User.id == uuid.UUID(user_id)
    ).first()
    if not user:
        raise UserNotFoundError()

    if user.is_verified:
        return

    purpose = (
        OTPPurpose.EMAIL_VERIFICATION.value
        if user.auth_provider == AuthProvider.EMAIL
        else OTPPurpose.PHONE_VERIFICATION.value
    )

    await check_resend_limit(redis, user_id, purpose)

    ttl = (
        settings.OTP_EXPIRE_MINUTES_EMAIL
        if user.auth_provider == AuthProvider.EMAIL
        else settings.OTP_EXPIRE_MINUTES_SMS
    )

    otp_code = await store_otp(
        redis=redis,
        user_id=user_id,
        purpose=purpose,
        ttl_minutes=ttl,
    )

    await increment_resend_counter(redis, user_id, purpose)

    print(f"[DEV] Resent OTP for user {user_id}: {otp_code}")


# --- Login ---

async def login_user(
    password: str,
    db: Session,
    redis: Redis,
    email: str | None = None,
    phone_number: str | None = None,
    device_name: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    country: str | None = None,
) -> LoginResponse:

    # Normalize
    if email:
        email = normalize_email(email)
    if phone_number:
        phone_number = normalize_phone(phone_number)

    # Fetch user
    if email:
        user = db.query(User).filter(User.email == email).first()
    else:
        user = db.query(User).filter(
            User.phone_number == phone_number
        ).first()

    # Use a consistent error for both "not found" and "wrong password"
    # Never reveal which one failed — that leaks account existence
    if not user:
        raise InvalidCredentialsError()

    if not user.is_active:
        raise AccountDisabledError()

    if user.is_locked:
        raise AccountLockedError()

    # Verify password
    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.ACCOUNT_LOCKOUT_THRESHOLD:
            user.is_locked = True
            user.locked_at = datetime.now(timezone.utc)
        db.commit()
        raise InvalidCredentialsError()

    if not user.is_verified:
        raise AccountNotVerifiedError()

    # Reset failed attempts on successful password verification
    user.failed_login_attempts = 0
    db.commit()

    # 2FA path
    if user.is_2fa_enabled:
        two_fa_token = await store_2fa_pending(redis, str(user.id))
        return LoginResponse(
            requires_2fa=True,
            two_fa_token=two_fa_token,
        )

    # No 2FA — issue tokens directly
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    tokens = await create_token_pair(
        user=user,
        db=db,
        redis=redis,
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        country=country,
    )

    return LoginResponse(requires_2fa=False, tokens=tokens)


# --- 2FA Login Verification ---

async def verify_2fa_login(
    two_fa_token: str,
    totp_code: str,
    db: Session,
    redis: Redis,
    device_name: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    country: str | None = None,
) -> TokenResponse:

    user_id = await consume_2fa_pending(redis, two_fa_token)

    user = db.query(User).filter(
        User.id == uuid.UUID(user_id)
    ).first()
    if not user:
        raise UserNotFoundError()

    _verify_totp_code(user, totp_code)

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    return await create_token_pair(
        user=user,
        db=db,
        redis=redis,
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        country=country,
    )


# --- Password Management ---

async def forgot_password(
    db: Session,
    redis: Redis,
    email: str | None = None,
    phone_number: str | None = None,
) -> None:

    if email:
        email = normalize_email(email)
        user = db.query(User).filter(User.email == email).first()
    else:
        phone_number = normalize_phone(phone_number)
        user = db.query(User).filter(
            User.phone_number == phone_number
        ).first()

    # Always return success even if user not found
    # Never confirm whether an account exists for a given email/phone
    if not user:
        return

    otp_code = await store_otp(
        redis=redis,
        user_id=str(user.id),
        purpose=OTPPurpose.PASSWORD_RESET.value,
        ttl_minutes=settings.OTP_EXPIRE_MINUTES_EMAIL,
    )

    print(f"[DEV] Password reset OTP for user {user.id}: {otp_code}")


async def reset_password(
    user_id: str,
    otp_code: str,
    new_password: str,
    db: Session,
    redis: Redis,
) -> None:

    user = db.query(User).filter(
        User.id == uuid.UUID(user_id)
    ).first()
    if not user:
        raise UserNotFoundError()

    await verify_otp(
        redis=redis,
        user_id=user_id,
        purpose=OTPPurpose.PASSWORD_RESET.value,
        submitted_code=otp_code,
    )

    user.hashed_password = hash_password(new_password)
    user.is_locked = False
    user.failed_login_attempts = 0
    db.commit()

    # Invalidate all sessions after password change
    await _invalidate_all_sessions(uuid.UUID(user_id), db, redis)

    await invalidate_otp(
        redis=redis,
        user_id=user_id,
        purpose=OTPPurpose.PASSWORD_RESET.value,
    )


async def change_password(
    user: User,
    current_password: str,
    new_password: str,
    db: Session,
    redis: Redis,
) -> None:

    if not verify_password(current_password, user.hashed_password):
        raise PasswordMismatchError()

    user.hashed_password = hash_password(new_password)
    db.commit()

    await _invalidate_all_sessions(user.id, db, redis)


# --- 2FA Setup ---

async def enable_2fa(
    user: User,
    db: Session,
) -> Enable2FAResponse:

    if user.is_2fa_enabled:
        raise TwoFactorAlreadyEnabledError()

    # Generate TOTP secret
    secret = pyotp.random_base32()

    # Build the OTP auth URI for QR code generation
    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(
        name=user.email or user.phone_number,
        issuer_name=settings.APP_NAME,
    )

    # Generate QR code as base64 PNG
    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()
    qr_code_url = f"data:image/png;base64,{qr_b64}"

    # Generate backup codes
    backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]
    hashed_backups = [hash_password(code) for code in backup_codes]

    # Store secret and backup codes — not yet enabled until verified
    user.totp_secret = encrypt_data(secret)
    db.commit()

    # Store hashed backup codes in Redis temporarily until setup confirmed
    # We will persist to DB in verify_2fa_setup
    return Enable2FAResponse(
        secret=secret,
        qr_code_url=qr_code_url,
        backup_codes=backup_codes,
    )


async def verify_2fa_setup(
    user: User,
    totp_code: str,
    db: Session,
) -> None:

    if user.is_2fa_enabled:
        raise TwoFactorAlreadyEnabledError()

    if not user.totp_secret:
        raise InvalidTokenError(detail="2FA setup not initiated")

    _verify_totp_code(user, totp_code)

    user.is_2fa_enabled = True
    db.commit()


async def disable_2fa(
    user: User,
    password: str,
    totp_code: str,
    db: Session,
) -> None:

    if not verify_password(password, user.hashed_password):
        raise PasswordMismatchError()

    _verify_totp_code(user, totp_code)

    user.is_2fa_enabled = False
    user.totp_secret = None
    user.totp_last_used = None
    db.commit()


# --- TOTP helper ---

def _verify_totp_code(user: User, totp_code: str) -> None:
    from app.core.security import decrypt_data
    from app.core.exceptions import InvalidOTPError

    if not user.totp_secret:
        raise InvalidOTPError(detail="2FA is not configured for this account")

    secret = decrypt_data(user.totp_secret)
    totp = pyotp.TOTP(secret)

    # valid_window=1 allows one 30-second window either side for clock skew
    current_counter = totp.timecode(datetime.now(timezone.utc))

    if not totp.verify(totp_code, valid_window=1):
        raise InvalidOTPError(detail="Invalid 2FA code")

    # Replay prevention — reject if this counter was already used
    if user.totp_last_used and user.totp_last_used >= current_counter:
        raise InvalidOTPError(detail="2FA code already used")