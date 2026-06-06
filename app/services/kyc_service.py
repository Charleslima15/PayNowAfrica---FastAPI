import httpx
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from fastapi import BackgroundTasks

from app.models.user import User, VerificationLevel
from app.models.kyc import KYCRecord, KYCStatus, IDType
from app.core.security import encrypt_data, decrypt_data
from app.core.exceptions import (
    BadRequestError,
    ExternalServiceError,
    InsufficientKYCLevelError,
)
from app.config import get_settings

settings = get_settings()


# --- Submit KYC ---

async def submit_kyc(
    user: User,
    id_type: str,
    id_number: str,
    country_code: str,
    db: Session,
    background_tasks: BackgroundTasks,
) -> KYCRecord:

    # Check if user already has an approved KYC record
    existing = db.query(KYCRecord).filter(
        KYCRecord.user_id == user.id,
        KYCRecord.status == KYCStatus.APPROVED,
    ).first()

    if existing:
        raise BadRequestError(detail="KYC already verified for this account")

    # Check for a pending submission
    pending = db.query(KYCRecord).filter(
        KYCRecord.user_id == user.id,
        KYCRecord.status == KYCStatus.PENDING,
    ).first()

    if pending:
        raise BadRequestError(
            detail="A KYC verification is already in progress"
        )

    # Map string id_type to enum
    try:
        id_type_enum = IDType[id_type.upper()]
    except KeyError:
        raise BadRequestError(detail=f"Invalid ID type: {id_type}")

    # Create KYC record with encrypted ID number
    record = KYCRecord(
        user_id=user.id,
        id_type=id_type_enum,
        status=KYCStatus.PENDING,
        encrypted_id_number=encrypt_data(id_number),
        verification_level=0,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Queue the Smile Identity call as a background task
    background_tasks.add_task(
        _run_smile_verification,
        record_id=str(record.id),
        user_id=str(user.id),
        id_type=id_type,
        id_number=id_number,
        country_code=country_code,
        first_name=user.first_name,
        last_name=user.last_name,
    )

    return record


# --- Background verification task ---

async def _run_smile_verification(
    record_id: str,
    user_id: str,
    id_type: str,
    id_number: str,
    country_code: str,
    first_name: str,
    last_name: str,
) -> None:
    from app.db.postgres import SessionLocal

    db = SessionLocal()
    try:
        record = db.query(KYCRecord).filter(
            KYCRecord.id == record_id
        ).first()

        if not record:
            return

        # Call Smile Identity
        result = await _call_smile_identity(
            id_type=id_type,
            id_number=id_number,
            country_code=country_code,
            first_name=first_name,
            last_name=last_name,
        )

        if result["success"]:
            # Compare returned name against registration name
            returned_first = result.get("first_name", "").lower().strip()
            returned_last = result.get("last_name", "").lower().strip()
            reg_first = first_name.lower().strip()
            reg_last = last_name.lower().strip()

            name_match = (
                returned_first == reg_first and
                returned_last == reg_last
            )

            if name_match:
                record.status = KYCStatus.APPROVED
                record.verification_level = 1
                record.verified_first_name = result.get("first_name")
                record.verified_last_name = result.get("last_name")
                record.verified_dob = result.get("dob")
                record.smile_job_id = result.get("job_id")
                record.verified_at = datetime.now(timezone.utc)

                # Update user KYC level
                user = db.query(User).filter(
                    User.id == user_id
                ).first()
                if user:
                    user.kyc_level = VerificationLevel.LEVEL_1

            else:
                # Name mismatch — flag for manual review
                record.status = KYCStatus.MANUAL_REVIEW
                record.failure_reason = (
                    f"Name mismatch: submitted {first_name} {last_name}, "
                    f"returned {result.get('first_name')} {result.get('last_name')}"
                )

        else:
            record.status = KYCStatus.FAILED
            record.failure_reason = result.get("error", "Verification failed")

        db.commit()

    except Exception as e:
        # Graceful degradation — log failure but don't crash
        if db:
            record = db.query(KYCRecord).filter(
                KYCRecord.id == record_id
            ).first()
            if record:
                record.status = KYCStatus.FAILED
                record.failure_reason = f"Service error: {str(e)}"
                db.commit()
    finally:
        db.close()

# --- Smile Identity API call ---

async def _call_smile_identity(
    id_type: str,
    id_number: str,
    country_code: str,
    first_name: str,
    last_name: str,
) -> dict:

    # Map our id_type to Smile Identity's id_type codes
    smile_id_type_map = {
        "nin": "NIN",
        "national_id": "NATIONAL_ID",
        "passport": "PASSPORT",
        "drivers_license": "DRIVERS_LICENSE",
    }

    smile_id_type = smile_id_type_map.get(id_type.lower(), id_type.upper())

    payload = {
        "source_sdk": "rest_api",
        "source_sdk_version": "1.0.0",
        "partner_id": settings.SMILE_PARTNER_ID,
        "partner_params": {
            "job_id": f"job_{id_number[-4:]}",
            "user_id": id_number,
            "job_type": 5,
        },
        "id_info": {
            "first_name": first_name,
            "last_name": last_name,
            "country": country_code,
            "id_type": smile_id_type,
            "id_number": id_number,
            "entered": True,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://testapi.smileidentity.com/v1/id_verification",
                json=payload,
                headers={
                    "Authorization": f"Bearer {settings.SMILE_API_KEY}",
                    "Content-Type": "application/json",
                },
            )

        if response.status_code == 200:
            data = response.json()
            actions = data.get("Actions", {})
            verified = actions.get("Verify_ID_Number") == "Verified"

            if verified:
                person = data.get("FullData", {})
                return {
                    "success": True,
                    "first_name": person.get("FirstName", ""),
                    "last_name": person.get("LastName", ""),
                    "dob": person.get("DOB", ""),
                    "job_id": data.get("SmileJobID", ""),
                }
            else:
                return {
                    "success": False,
                    "error": "ID could not be verified",
                }

        else:
            return {
                "success": False,
                "error": f"Smile Identity returned status {response.status_code}",
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Verification service timed out",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


# --- Get KYC status ---

async def get_kyc_status(
    user: User,
    db: Session,
) -> dict:

    record = (
        db.query(KYCRecord)
        .filter(KYCRecord.user_id == user.id)
        .order_by(KYCRecord.created_at.desc())
        .first()
    )

    if not record:
        return {
            "kyc_level": 0,
            "status": "not_submitted",
            "id_type": None,
            "verified_at": None,
            "failure_reason": None,
        }

    # Map enum value to integer level
    level_map = {
        "level_0": 0,
        "level_1": 1,
        "level_2": 2,
    }

    return {
        "kyc_level": level_map.get(user.kyc_level.value, 0),
        "status": record.status.value,
        "id_type": record.id_type.value,
        "verified_at": record.verified_at,
        "failure_reason": record.failure_reason,
    }