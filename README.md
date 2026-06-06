# PayNow Africa — Authentication Service

Production-grade multi-platform authentication API for the PayNow Africa fintech platform.

## Stack
- FastAPI + Python 3.10
- PostgreSQL 14 (SQLAlchemy + Alembic)
- Redis 7 (OTP, sessions, token blacklist)
- Railway (deployment)

## Features
- Email and phone number registration with OTP verification
- JWT authentication (access + refresh tokens with rotation)
- Two-factor authentication (TOTP — Google Authenticator compatible)
- Password reset and change flows
- KYC verification via Smile Identity (async background processing)
- Session management with per-device revocation
- Account lockout after failed attempts
- Rate limiting and replay attack prevention

## Local Setup

### Prerequisites
- Python 3.10+
- PostgreSQL 14+
- Redis 7+ (or Docker)

### Installation

```bash
git clone https://github.com/yourusername/paynow-auth
cd paynow-auth
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Fill in .env values
alembic upgrade head
uvicorn app.main:app --reload
```

### Redis via Docker
```bash
docker run -d --name paynow-redis -p 6379:6379 redis:7
```

## API Documentation
Available at `/docs` when `DEBUG=true`.

## Environment Variables
See `.env.example` for all required variables.

## Deployment
Deployed on Railway. Push to main branch triggers automatic deployment.