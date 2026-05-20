import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum
from sqlalchemy.orm import relationship

from app.db.postgres import Base


class VerificationLevel(enum.Enum):
    LEVEL_0 = "level_0"  # Unverified
    LEVEL_1 = "level_1"  # Basic KYC
    LEVEL_2 = "level_2"  # Enhanced KYC


class AuthProvider(enum.Enum):
    EMAIL = "email"
    PHONE = "phone"

class User(Base):
    __tablename__ = "users"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Identity fields
    email: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True, index=True
    )
    phone_number: Mapped[str | None] = mapped_column(
        String(20), unique=True, nullable=True, index=True
    )
    auth_provider: Mapped[AuthProvider] = mapped_column(
        SAEnum(AuthProvider), nullable=False
    )

    # Security fields
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_locked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # 2FA fields
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_2fa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_last_used: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Profile fields
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    country_code: Mapped[str | None] = mapped_column(String(3), nullable=True)

    # KYC fields
    kyc_level: Mapped[VerificationLevel] = mapped_column(
        SAEnum(VerificationLevel),
        default=VerificationLevel.LEVEL_0,
        nullable=False,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Relationships
    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    otp_records: Mapped[list["OTPRecord"]] = relationship(
        "OTPRecord", back_populates="user", cascade="all, delete-orphan"
    )
    kyc_records: Mapped[list["KYCRecord"]] = relationship(
        "KYCRecord", back_populates="user", cascade="all, delete-orphan"
    )