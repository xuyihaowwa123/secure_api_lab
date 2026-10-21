# Secure REST API Lab Project & CVE Analysis

This project implements a secure REST API based on Python Flask. It provides JWT-based user authentication, access control for protected endpoints, and security countermeasures against SQL Injection and XSS. A GitHub Actions CI/CD pipeline is configured to run automated security scanning with Bandit (SAST) and Safety (SCA).

## 1. Environment & Dependencies
- **Language/Framework**: Python 3.8, Flask
- **Packages**: Flask-SQLAlchemy, bcrypt, pyjwt, python-dotenv
- **Database**: SQLite
- **Testing tool**: Postman

## 2. API Endpoints
| Method | Endpoint | Description | Require JWT Token |
|--------|----------|-------------|-------------------|
| POST | `/auth/login` | User login, returns JWT access token | No |
| GET | `/api/data` | Return protected business data | Yes |
| GET | `/api/user/profile` | Get profile information of current logged-in user | Yes |

1. **`POST /auth/login`**
   - Accept username and password in JSON request body.
   - Verify hashed user credentials and return a JWT token upon successful authentication.
2. **`GET /api/data`**
   - Require request header: `Authorization: Bearer <token>`
   - Reject requests without valid token and return 401 Unauthorized.
3. **`GET /api/user/profile`**
   - Custom endpoint to fetch current user ID and username.
   - Valid JWT token is mandatory for access.

> **Test account**: username `admin`, password `password123!`

## 3. Implementation of Security Measures
- **SQL Injection (SQLi) Protection**: 
  - Used Parameterized Queries / ORM (SQLAlchemy) to interact with the database. Strictly avoided string concatenation when forming SQL queries.
- **XSS Protection**: 
  - Sanitized (escaped) all user-provided data before returning it in API responses.
- **Broken Authentication Protection**: 
  - **Password Hashing**: Passwords are never stored in plaintext. They are hashed using `bcrypt`.
  - **JWT Implementation**: Issued JWT tokens upon successful login. Wrote middleware to verify the JWT signature and expiration on all protected routes.

## 4. CI/CD Pipeline & Security Scanning
The CI/CD pipeline is configured using GitHub Actions (`.github/workflows/ci.yml`). It runs automatically on every push and pull request.
- **SAST (Static Application Security Testing)**: Configured `Bandit` to scan the source code for security flaws.
- **SCA (Software Composition Analysis)**: Configured `Safety` to check dependencies for known vulnerabilities.

### Pipeline Results
![CI Pipeline](<screenshots/屏幕截图 2026-10-19 224226.png>)

### SAST/SCA Reports
![SAST and SCA Scan](<screenshots/屏幕截图 2026-10-19 224436.png>)

## 5. API Testing (Postman/curl)
Tested the API using Postman to ensure authentication works and access without a token is denied.

### 5.1 Login and obtain JWT token
- **Method**: `POST`
- **URL**: `http://127.0.0.1:5000/auth/login`
- **Body** → raw → JSON
```json
{
    "username":"admin",
    "password":"password123!"
}
