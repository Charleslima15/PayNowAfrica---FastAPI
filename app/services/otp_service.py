import random
import json
from datetime import datetime, timezone
from typing import Optional

from redis.asyncio import Redis

from app.config import get_settings
from app.core.exceptions import (
    InvalidOTPError,
    OTPExpiredError,
    OTPAlreadyUsedError,
    RateLimitExceededError,
    OTPResendLimitError,
)

settings = get_settings()

# --- Redis key builders ---

def _otp_key(user_id: str, purpose: str) -> str:
    return f"otp:{purpose}:{user_id}"

def _attempts_key(user_id: str, purpose: str) -> str:
    return f"otp_attempts:{purpose}:{user_id}"

def _resend_key(user_id: str, purpose: str) -> str:
    return f"otp_resend:{purpose}:{user_id}"

# --- OTP generation ---

def generate_otp() -> str:
    """Generate a cryptographically random 6-digit OTP."""
    return f"{random.SystemRandom().randint(0, 999999):06d}"

# --- Store OTP ---

async def store_otp(
    redis: Redis,
    user_id: str,
    purpose: str,
    ttl_minutes: int,
) -> str:
    code = generate_otp()

    payload = json.dumps({
        "code": code,
        "used": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    key = _otp_key(user_id, purpose)
    await redis.setex(key, ttl_minutes * 60, payload)

    return code

# --- Verify OTP ---

async def verify_otp(
    redis: Redis,
    user_id: str,
    purpose: str,
    submitted_code: str,
) -> bool:
    otp_key = _otp_key(user_id, purpose)
    attempts_key = _attempts_key(user_id, purpose)

    # Check attempt count before anything else
    attempts = await redis.get(attempts_key)
    if attempts and int(attempts) >= settings.OTP_MAX_ATTEMPTS:
        raise RateLimitExceededError(
            detail="Too many incorrect attempts. Please request a new OTP"
        )

    # Fetch the stored OTP payload
    raw = await redis.get(otp_key)
    if not raw:
        raise OTPExpiredError()

    payload = json.loads(raw)

    # Single-use enforcement
    if payload["used"]:
        raise OTPAlreadyUsedError()

    # Constant-time comparison to prevent timing attacks
    stored_code = payload["code"]
    if not _constant_time_compare(submitted_code, stored_code):
        # Increment attempt counter with same TTL as OTP
        ttl = await redis.ttl(otp_key)
        await redis.setex(attempts_key, ttl, int(attempts or 0) + 1)
        raise InvalidOTPError()

    # Mark as used — update payload in Redis rather than deleting
    payload["used"] = True
    ttl = await redis.ttl(otp_key)
    await redis.setex(otp_key, ttl, json.dumps(payload))

    return True


# --- Resend throttle ---

async def check_resend_limit(
    redis: Redis,
    user_id: str,
    purpose: str,
) -> None:
    key = _resend_key(user_id, purpose)
    count = await redis.get(key)

    if count and int(count) >= settings.OTP_RESEND_LIMIT:
        raise OTPResendLimitError()


async def increment_resend_counter(
    redis: Redis,
    user_id: str,
    purpose: str,
) -> None:
    key = _resend_key(user_id, purpose)
    count = await redis.get(key)

    if count is None:
        await redis.setex(
            key,
            settings.OTP_RESEND_WINDOW_MINUTES * 60,
            1
        )
    else:
        await redis.incr(key)

# --- Invalidate OTP ---

async def invalidate_otp(
    redis: Redis,
    user_id: str,
    purpose: str,
) -> None:
    """Explicitly delete an OTP — used after password reset completes."""
    await redis.delete(_otp_key(user_id, purpose))
    await redis.delete(_attempts_key(user_id, purpose))

# --- Timing attack prevention ---

def _constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings in constant time regardless of where they differ."""
    if len(val1) != len(val2):
        return False
    result = 0
    for a, b in zip(val1, val2):
        result |= ord(a) ^ ord(b)
    return result == 0