from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserProfileResponse(BaseModel):
    user_id: str
    first_name: str
    last_name: str
    email: Optional[str] = None
    phone_number: Optional[str] = None
    country_code: Optional[str] = None
    is_verified: bool
    is_2fa_enabled: bool
    kyc_level: str
    created_at: datetime
    last_login_at: Optional[datetime] = None


class UpdateProfileRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    country_code: Optional[str] = None


class SessionResponse(BaseModel):
    session_id: str
    device_name: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    created_at: datetime
    last_active_at: datetime
    is_current: bool

