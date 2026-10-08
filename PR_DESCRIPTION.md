# Fix OWASP Top 10 issues in SecureNotes

This pull request fixes six security risks in the SecureNotes student starter.

- **A01 Broken Access Control:** Restrict each note lookup to its owner.
- **A02 Security Misconfiguration:** Limit CORS, use an environment secret, and hide error tracebacks.
- **A04 Cryptographic Failures:** Salt/hash stored passwords using PBKDF2.
- **A05 Injection:** Parameterize the login SQL query.
- **A07 Authentication Failures:** Introduce signed expiring bearer tokens and generic login errors.
- **A10 Mishandling of Exceptional Conditions:** Deny access when the admin permission check fails.

**Verification:** Run `python SECURITY_TESTS.py` and manually exercise register, login, and notes in `/docs`.
