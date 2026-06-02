from fastapi import HTTPException, status

# --- Base ---

class AppException(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=self.status_code, detail=detail)

# --- 400 Bad Request ---

class BadRequestError(AppException):
    status_code = status.HTTP_400_BAD_REQUEST


class InvalidOTPError(AppException):
    status_code = status.HTTP_400_BAD_REQUEST
    def __init__(self, detail: str = "Invalid or expired OTP"):
        super().__init__(detail=detail)


class OTPExpiredError(AppException):
    status_code = status.HTTP_400_BAD_REQUEST
    def __init__(self, detail: str = "OTP has expired"):
        super().__init__(detail=detail)


class OTPAlreadyUsedError(AppException):
    status_code = status.HTTP_400_BAD_REQUEST
    def __init__(self, detail: str = "OTP has already been used"):
        super().__init__(detail=detail)


class PasswordMismatchError(AppException):
    status_code = status.HTTP_400_BAD_REQUEST
    def __init__(self, detail: str = "Current password is incorrect"):
        super().__init__(detail=detail)


class WeakPasswordError(AppException):
    status_code = status.HTTP_400_BAD_REQUEST
    def __init__(self, detail: str = "Password does not meet complexity requirements"):
        super().__init__(detail=detail)


class InvalidTokenError(AppException):
    status_code = status.HTTP_400_BAD_REQUEST
    def __init__(self, detail: str = "Invalid or expired token"):
        super().__init__(detail=detail)

# --- 401 Unauthorized ---

class InvalidCredentialsError(AppException):
    status_code = status.HTTP_401_UNAUTHORIZED
    def __init__(self, detail: str = "Invalid email/phone or password"):
        super().__init__(detail=detail)


class TokenExpiredError(AppException):
    status_code = status.HTTP_401_UNAUTHORIZED
    def __init__(self, detail: str = "Token has expired"):
        super().__init__(detail=detail)


class NotAuthenticatedError(AppException):
    status_code = status.HTTP_401_UNAUTHORIZED
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(detail=detail)

# --- 403 Forbidden ---

class AccountNotVerifiedError(AppException):
    status_code = status.HTTP_403_FORBIDDEN
    def __init__(self, detail: str = "Account not verified. Please verify your email or phone number"):
        super().__init__(detail=detail)


class AccountLockedError(AppException):
    status_code = status.HTTP_403_FORBIDDEN
    def __init__(self, detail: str = "Account locked due to too many failed attempts"):
        super().__init__(detail=detail)


class AccountDisabledError(AppException):
    status_code = status.HTTP_403_FORBIDDEN
    def __init__(self, detail: str = "Account has been disabled"):
        super().__init__(detail=detail)


class TwoFactorRequiredError(AppException):
    status_code = status.HTTP_403_FORBIDDEN
    def __init__(self, detail: str = "Two-factor authentication required"):
        super().__init__(detail=detail)


class InsufficientKYCLevelError(AppException):
    status_code = status.HTTP_403_FORBIDDEN
    def __init__(self, detail: str = "KYC verification required for this action"):
        super().__init__(detail=detail)


class PermissionDeniedError(AppException):
    status_code = status.HTTP_403_FORBIDDEN
    def __init__(self, detail: str = "You do not have permission to perform this action"):
        super().__init__(detail=detail)

# --- 404 Not Found ---

class UserNotFoundError(AppException):
    status_code = status.HTTP_404_NOT_FOUND
    def __init__(self, detail: str = "User not found"):
        super().__init__(detail=detail)


class SessionNotFoundError(AppException):
    status_code = status.HTTP_404_NOT_FOUND
    def __init__(self, detail: str = "Session not found"):
        super().__init__(detail=detail)

# --- 409 Conflict ---

class EmailAlreadyExistsError(AppException):
    status_code = status.HTTP_409_CONFLICT
    def __init__(self, detail: str = "An account with this email already exists"):
        super().__init__(detail=detail)


class PhoneAlreadyExistsError(AppException):
    status_code = status.HTTP_409_CONFLICT
    def __init__(self, detail: str = "An account with this phone number already exists"):
        super().__init__(detail=detail)


class TwoFactorAlreadyEnabledError(AppException):
    status_code = status.HTTP_409_CONFLICT
    def __init__(self, detail: str = "Two-factor authentication is already enabled"):
        super().__init__(detail=detail)

# --- 429 Too Many Requests ---

class RateLimitExceededError(AppException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    def __init__(self, detail: str = "Too many requests. Please try again later"):
        super().__init__(detail=detail)


class OTPResendLimitError(AppException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    def __init__(self, detail: str = "OTP resend limit reached. Please try again in an hour"):
        super().__init__(detail=detail)


class MaxSessionsExceededError(AppException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    def __init__(self, detail: str = "Maximum concurrent sessions reached"):
        super().__init__(detail=detail)

# --- 503 Service Unavailable ---

class ExternalServiceError(AppException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    def __init__(self, detail: str = "An external service is temporarily unavailable"):
        super().__init__(detail=detail)