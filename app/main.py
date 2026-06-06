from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.kyc import router as kyc_router



# from app.api.admin import router as admin_router
# app.include_router(admin_router, prefix="/admin", tags=["Admin"])

from app.config import get_settings
from app.core.exceptions import AppException

settings = get_settings()

# app = FastAPI(
#     title=settings.APP_NAME,
#     version="1.0.0",
#     description="Multi-Platform Authentication Service for PayNow Africa",
#     docs_url="/docs",
#     redoc_url="/redoc",
#     openapi_url="/openapi.json",
# )

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Multi-Platform Authentication Service for PayNow Africa",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

# --- CORS ---
origins = (
    ["*"] if settings.DEBUG
    else ["https://paynow-africa.com", "https://app.paynow-africa.com"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# --- Exception handlers ---

@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "An unexpected error occurred",
        },
    )

# --- Health check ---

@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "success": True,
        "message": "PayNow Africa Auth Service is running",
        "version": "1.0.0",
    }

from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.kyc import router as kyc_router
from app.api.admin import router as admin_router

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(users_router, prefix="/users", tags=["Users"])
app.include_router(kyc_router, prefix="/kyc", tags=["KYC"])
app.include_router(admin_router, prefix="/admin", tags=["Admin"])