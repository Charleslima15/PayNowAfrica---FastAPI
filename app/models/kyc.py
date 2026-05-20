import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Text, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum
from sqlalchemy import String, DateTime, ForeignKey, Text, Enum as SAEnum, Integer

from app.db.postgres import Base

class KYCStatus(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    FAILED = "failed"
    MANUAL_REVIEW = "manual_review"


class IDType(enum.Enum):
    NIN = "nin"               # Nigeria
    NATIONAL_ID = "national_id"  # Kenya, South Africa
    PASSPORT = "passport"     # All countries
    DRIVERS_LICENSE = "drivers_license"


class KYCRecord(Base):
    __tablename__ = "kyc_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Verification details
    id_type: Mapped[IDType] = mapped_column(SAEnum(IDType), nullable=False)
    status: Mapped[KYCStatus] = mapped_column(
        SAEnum(KYCStatus), default=KYCStatus.PENDING, nullable=False
    )
    verification_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Encrypted storage — raw ID numbers are never stored in plaintext
    encrypted_id_number: Mapped[str] = mapped_column(Text, nullable=False)

    # Data returned from Smile Identity
    verified_first_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verified_last_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verified_dob: Mapped[str | None] = mapped_column(String(20), nullable=True)
    smile_job_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Failure tracking
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    admin_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationship
    user: Mapped["User"] = relationship("User", back_populates="kyc_records")