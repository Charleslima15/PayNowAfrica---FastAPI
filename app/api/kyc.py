from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session

from app.core.dependencies import get_db, get_current_verified_user
from app.models.user import User
from app.schemas.kyc import KYCSubmitRequest, KYCStatusResponse
from app.schemas.common import SuccessResponse
from app.services import kyc_service

router = APIRouter()


@router.post("/verify", response_model=SuccessResponse)
async def submit_kyc(
    payload: KYCSubmitRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
):
    await kyc_service.submit_kyc(
        user=current_user,
        id_type=payload.id_type,
        id_number=payload.id_number,
        country_code=payload.country_code,
        db=db,
        background_tasks=background_tasks,
    )
    return SuccessResponse(
        message="KYC verification submitted. You will be notified once verified"
    )


@router.get("/status", response_model=SuccessResponse[KYCStatusResponse])
async def get_kyc_status(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
):
    status = await kyc_service.get_kyc_status(
        user=current_user,
        db=db,
    )
    return SuccessResponse(
        message="KYC status retrieved",
        data=KYCStatusResponse(**status),
    )