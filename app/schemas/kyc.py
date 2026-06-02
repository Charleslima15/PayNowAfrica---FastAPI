from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime
import re

class KYCSubmitRequest(BaseModel):
    id_type: str
    id_number: str
    country_code: str

    @field_validator("id_type")
    @classmethod
    def valid_id_type(cls, v: str) -> str:
        allowed = {"nin", "national_id", "passport", "drivers_license"}
        if v.lower() not in allowed:
            raise ValueError(f"id_type must be one of: {', '.join(allowed)}")
        return v.lower()

    @field_validator("id_number")
    @classmethod
    def id_number_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ID number cannot be empty")
        return v

    @field_validator("country_code")
    @classmethod
    def valid_country_code(cls, v: str) -> str:
        allowed = {"NG", "KE", "ZA", "GH", "TZ"}
        if v.upper() not in allowed:
            raise ValueError(f"country_code must be one of: {', '.join(allowed)}")
        return v.upper()


class KYCStatusResponse(BaseModel):
    kyc_level: int
    status: str
    id_type: Optional[str] = None
    verified_at: Optional[datetime] = None
    failure_reason: Optional[str] = None