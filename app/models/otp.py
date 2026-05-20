import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Integer, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.db.postgres import Base

class OTPPurpose(enum.Enum):
    EMAIL_VERIFICATION = "email_verification"
    PHONE_VERIFICATION = "phone_verification"
    PASSWORD_RESET = "password_reset"
    PHONE_CHANGE = "phone_change"
    EMAIL_CHANGE = "email_change"

class OTPRecord(Base):
    __tablename__ = "otp_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # OTP data
    purpose: Mapped[OTPPurpose] = mapped_column(SAEnum(OTPPurpose), nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationship
    user: Mapped["User"] = relationship("User", back_populates="otp_records")