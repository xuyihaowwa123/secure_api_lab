# Secure REST API Lab Project
This project implements a secure REST API based on Python Flask. It provides JWT‑based user authentication, access control for protected endpoints, and security countermeasures against SQL Injection and XSS. GitHub Actions CI/CD pipeline is configured to run automated security scanning with Bandit (SAST) and Safety (SCA).

## Environment & Dependencies
- Python 3.8
- Packages: Flask, Flask‑SQLAlchemy, bcrypt, pyjwt, python‑dotenv
- Database: SQLite
- Testing tool: Postman

## API Endpoints
| Method | Endpoint | Description | Require JWT Token |
|--------|----------|-------------|-------------------|
| POST | `/auth/login` | User login, returns JWT access token | No |
| GET | `/api/data` | Return protected business data | Yes |
| GET | `/api/user/profile` | Get profile information of current logged‑in user | Yes |

1. `POST /auth/login`
- Accept username and password in JSON request body.
- Verify hashed user credentials and return a JWT token upon successful authentication.

2. `GET /api/data`
- Require request header: `Authorization: Bearer <token>`
- Reject requests without valid token and return 401 Unauthorized.

3. `GET /api/user/profile`
- Custom endpoint to fetch current user ID and username.
- Valid JWT token is mandatory for access.

> Test account: username `admin`, password `password123!`

## Postman Test Procedures
1. Start application: `python app.py`, service address: `http://127.0.0.1:5000`

### ① Login and obtain JWT token
- Method: `POST`
- URL: `http://127.0.0.1:5000/auth/login`
- Body → raw → JSON
```json
{
    "username":"admin",
    "password":"password123!"
}
