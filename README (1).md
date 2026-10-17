# MERKINY PRO — Full Auth Backend

## Features

- Register (one email = one account)
- Login with **bcrypt** password hashes
- JWT sessions (Bearer token)
- Email verification codes (dev mode returns code in JSON; plug in SMTP later)
- Password reset + change password
- 5-day trial + admin subscription unlock
- Optional paper-state sync (`positions`, `trades`, `favourites`)
- SQLite database (`merkiny.db`)

## Quick start

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # edit secrets
python app.py
```

Health check: `GET http://127.0.0.1:5055/api/health`

## API overview

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | — | Health |
| POST | `/api/auth/register` | — | `{email,name,password}` |
| POST | `/api/auth/login` | — | `{email,password}` → token + user |
| POST | `/api/auth/logout` | Bearer | Revoke session |
| GET | `/api/auth/me` | Bearer | Current user |
| POST | `/api/auth/send-code` | — | `{email,purpose}` |
| POST | `/api/auth/verify-email` | — | `{email,code}` → token |
| POST | `/api/auth/reset-password` | — | `{email,code,password}` |
| POST | `/api/auth/change-password` | Bearer | `{oldPassword,newPassword,code}` |
| POST | `/api/admin/unlock` | admin key | `{uid,key,days}` |
| POST | `/api/unlock` | admin key | Alias for unlock |
| GET | `/api/admin/users` | `X-Admin-Key` | List users |
| POST | `/api/user/sync` | Bearer | Push cash/positions/trades |
| GET | `/api/user/state` | Bearer | Pull saved paper state |

### Register response (dev)

Verification code is returned in `data.verification.code` until SMTP is configured.

### Front-end wiring

In the browser (or in your hosted app bootstrap):

```js
localStorage.setItem('tm_api_base', 'http://127.0.0.1:5055');
// After login:
localStorage.setItem('tm_auth_token', token);
```

Authorization header on protected calls:

```http
Authorization: Bearer <token>
```

## Security checklist

1. Change `MERKINY_ADMIN_KEY` and `MERKINY_JWT_SECRET`
2. Serve API over HTTPS in production
3. Restrict `MERKINY_CORS_ORIGINS` to your real domain
4. Add SMTP for real email codes
5. Back up `merkiny.db`
6. Rate-limit `/api/auth/*` at the reverse proxy

## Note on the current HTML app

The shipped `index.html` still defaults to **localStorage** auth. Point it at this API by setting `tm_api_base` and adapting `doLogin` / `doRegister` / verify flows to call these endpoints (or ask to wire the HTML fully to this backend next).
