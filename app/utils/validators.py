import re
from typing import Optional

def normalize_phone(phone: str) -> str:
    """Strip spaces and dashes, ensure E.164 format is preserved."""
    return re.sub(r"[\s\-]", "", phone.strip())


def normalize_email(email: str) -> str:
    """Lowercase and strip whitespace."""
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def is_valid_phone(phone: str) -> bool:
    """Validates E.164 format: + followed by 8 to 15 digits."""
    pattern = r"^\+[1-9]\d{7,14}$"
    return bool(re.match(pattern, phone))


def mask_email(email: str) -> str:
    """Returns j***@gmail.com — safe for logs and responses."""
    parts = email.split("@")
    if len(parts) != 2:
        return "***"
    local, domain = parts
    return f"{local[0]}***@{domain}"


def mask_phone(phone: str) -> str:
    """Returns +234***7890 — safe for logs and responses."""
    if len(phone) < 6:
        return "***"
    return f"{phone[:4]}***{phone[-4:]}"