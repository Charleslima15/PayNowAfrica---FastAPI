from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import EmailStr
from functools import lru_cache

class Settings(BaseSettings):
    # App
    APP_NAME: str = "PayNow Africa Auth Service"
    DEBUG: bool = False
    SECRET_KEY: str
    ALGORITHM: str = "HS256"

    # Database
    DATABASE_URL: str
    REDIS_URL: str

    # JWT
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # OTP
    OTP_EXPIRE_MINUTES_EMAIL: int = 10
    OTP_EXPIRE_MINUTES_SMS: int = 5
    OTP_MAX_ATTEMPTS: int = 3
    OTP_RESEND_LIMIT: int = 3
    OTP_RESEND_WINDOW_MINUTES: int = 60

    # Rate limiting
    LOGIN_ATTEMPT_LIMIT: int = 5
    LOGIN_ATTEMPT_WINDOW_MINUTES: int = 15
    ACCOUNT_LOCKOUT_THRESHOLD: int = 10
    REGISTRATION_LIMIT: int = 3
    REGISTRATION_WINDOW_MINUTES: int = 60

    # Sessions
    MAX_CONCURRENT_SESSIONS: int = 5
    SESSION_INACTIVITY_TIMEOUT_MINUTES: int = 30

    # Email
    SENDGRID_API_KEY: str
    FROM_EMAIL: EmailStr

    # SMS
    AT_USERNAME: str
    AT_API_KEY: str

    # KYC
    SMILE_PARTNER_ID: str
    SMILE_API_KEY: str
    SMILE_ENVIRONMENT: str = "sandbox"

    # Encryption
    ENCRYPTION_KEY: str

    # class Config:
    #     env_file = ".env"
    #     case_sensitive = True
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

@lru_cache()
def get_settings() -> Settings:
    return Settings()

# if __name__ == "__main__":
#     settings = get_settings()
#     print(f"App: {settings.APP_NAME}")
#     print(f"Debug: {settings.DEBUG}")
#     print(f"DB: {settings.DATABASE_URL[:20]}...")