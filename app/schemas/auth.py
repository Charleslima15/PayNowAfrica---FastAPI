from pydantic import BaseModel, EmailStr, field_validator, model_validator
from typing import Optional
import re

# --- Reusable password validator ---

def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one number")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValueError("Password must contain at least one special character")
    return password

# --- Registration ---

class RegisterRequest(BaseModel):
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    password: str
    country_code: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)

    @field_validator("phone_number")
    @classmethod
    def phone_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        pattern = r"^\+[1-9]\d{7,14}$"
        if not re.match(pattern, v):
            raise ValueError("Phone number must be in E.164 format e.g. +2348012345678")
        return v

    @field_validator("first_name", "last_name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name cannot be empty")
        if len(v) > 100:
            raise ValueError("Name cannot exceed 100 characters")
        return v

    @model_validator(mode="after")
    def email_or_phone_required(self) -> "RegisterRequest":
        if not self.email and not self.phone_number:
            raise ValueError("Either email or phone number is required")
        return self


class RegisterResponse(BaseModel):
    user_id: str
    message: str
    auth_provider: str

# --- OTP ---

class VerifyOTPRequest(BaseModel):
    user_id: str
    otp_code: str

    @field_validator("otp_code")
    @classmethod
    def otp_format(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("OTP must be exactly 6 digits")
        return v


class ResendOTPRequest(BaseModel):
    user_id: str

# --- Login ---

class LoginRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    password: str

    @model_validator(mode="after")
    def email_or_phone_required(self) -> "LoginRequest":
        if not self.email and not self.phone_number:
            raise ValueError("Either email or phone number is required")
        return self


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginResponse(BaseModel):
    requires_2fa: bool = False
    two_fa_token: Optional[str] = None
    tokens: Optional[TokenResponse] = None

# --- Token refresh and logout ---

class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str

# --- Password management ---

class ForgotPasswordRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None

    @model_validator(mode="after")
    def email_or_phone_required(self) -> "ForgotPasswordRequest":
        if not self.email and not self.phone_number:
            raise ValueError("Either email or phone number is required")
        return self


class ResetPasswordRequest(BaseModel):
    user_id: str
    otp_code: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)
    
# --- 2FA ---

class Enable2FAResponse(BaseModel):
    secret: str
    qr_code_url: str
    backup_codes: list[str]


class Verify2FASetupRequest(BaseModel):
    totp_code: str

    @field_validator("totp_code")
    @classmethod
    def code_format(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("TOTP code must be exactly 6 digits")
        return v


class Verify2FALoginRequest(BaseModel):
    two_fa_token: str
    totp_code: str


class Disable2FARequest(BaseModel):
    password: str
    totp_code: str