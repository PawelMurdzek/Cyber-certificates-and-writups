# Secure Development & OWASP

## OWASP Resources

| Resource | URL |
| :--- | :--- |
| **Cheat Sheet Series** | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/) |
| **Top 10 Web Risks** | [owasp.org/Top10](https://owasp.org/Top10/) |
| **ASVS (Verification Standard)** | [owasp.org/ASVS](https://owasp.org/www-project-application-security-verification-standard/) |
| **Testing Guide** | [owasp.org/testing-guide](https://owasp.org/www-project-web-security-testing-guide/) |

## OWASP Top 10 (2021)

| # | Vulnerability | Prevention |
| :--- | :--- | :--- |
| A01 | **Broken Access Control** | Deny by default, validate permissions server-side |
| A02 | **Cryptographic Failures** | Use strong encryption, don't store sensitive data unnecessarily |
| A03 | **Injection** | Parameterized queries, input validation, escape output |
| A04 | **Insecure Design** | Threat modeling, secure design patterns |
| A05 | **Security Misconfiguration** | Hardened configs, remove defaults, automate verification |
| A06 | **Vulnerable Components** | Inventory dependencies, patch regularly, use SCA tools |
| A07 | **Auth Failures** | MFA, strong passwords, rate limiting, secure session mgmt |
| A08 | **Data Integrity Failures** | Verify signatures, use trusted sources, CI/CD security |
| A09 | **Logging Failures** | Log security events, protect logs, alerting |
| A10 | **SSRF** | Validate URLs, allowlist, segment networks |

## Input Validation

```
DO:
- Validate on server-side (never trust client)
- Use allowlists over denylists
- Validate data type, length, format, range
- Encode output based on context (HTML, URL, JS, SQL)

DON'T:
- Trust user input
- Use regex alone for security
- Rely on client-side validation
```

## Authentication Best Practices

| Practice | Implementation |
| :--- | :--- |
| **Password Storage** | bcrypt, Argon2, scrypt (never MD5/SHA1) |
| **Session Management** | Secure, HttpOnly, SameSite cookies |
| **MFA** | TOTP, hardware keys, push notifications |
| **Rate Limiting** | Limit login attempts, implement lockouts |
| **Password Policy** | Min 12 chars, check against breached lists |

## Security Headers

| Header | Value | Purpose |
| :--- | :--- | :--- |
| `Content-Security-Policy` | `default-src 'self'` | Prevent XSS, injection |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer info |
