# Vulnerability Findings — Week 13 SecureNotes

| # | OWASP 2025 code & name | Where (original starter) | How an attacker abuses it | Fix |
|---|---|---|---|---|
| 1 | A01 Broken Access Control | `GET /notes/{note_id}` | Alice requests `/notes/2` to read Bob's private note because the original SQL checks only the note ID. | Query using both note ID and authenticated owner ID. |
| 2 | A02 Security Misconfiguration | App config and global exception handler | Any origin is accepted; the source contains a signing secret; server errors expose internal exception details and tracebacks. | Configure specific CORS origins, load the secret from the environment (random for local use), and return generic server errors. |
| 3 | A04 Cryptographic Failures | Database seed and `POST /register` | An attacker who gains access to the users table obtains every password in readable form. | Salt and hash passwords with PBKDF2-HMAC-SHA256; verify with constant-time comparison. |
| 4 | A05 Injection | `POST /login` | The username is concatenated into SQL; an attacker can change the query with crafted username input. | Use a parameterized `WHERE username = ?` query. |
| 5 | A07 Authentication Failures | `POST /login`, `current_user` | User IDs act as guessable, permanent bearer tokens; different login errors reveal whether a username exists. | Use signed, unpredictable, expiring bearer tokens and a generic invalid-credentials response. |
| 6 | A10 Mishandling of Exceptional Conditions | `GET /admin/users` | The `try/except: pass` catches a denied admin check and proceeds to return the users table. | Reject unauthenticated callers and return 403 immediately for non-admins. |

## Reflection

I think broken access control (A01) could cause the most damage because it lets one user read another user's private notes just by changing an ID in the URL. In a real application, these records could contain personal or confidential information. Attackers could repeat the request against many IDs and collect information from several accounts. Checking ownership on every note request makes sure users only see their own data.

## Checks to demonstrate

- Log in as Alice and access `/notes/2`: expect **404** after the fix.
- Send a username such as `' OR '1'='1` to `/login`: expect **401**.
- Request `/admin/users` with a made-up token: expect **401**.
- Request `/admin/users` using Alice's valid token: expect **403**.
- Log in as Alice and request `/notes`: expect only Alice's notes.
- Register a new user and log in: both should work.
- Confirm no readable passwords appear in the users table or admin API response.
