# Secure Development & OWASP

## OWASP Resources

| Resource | URL |
| :--- | :--- |
| **Cheat Sheet Series** | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/) |
| **Top 10 Web Risks** | [owasp.org/Top10](https://owasp.org/Top10/) |
| **ASVS (Verification Standard)** | [owasp.org/ASVS](https://owasp.org/www-project-application-security-verification-standard/) |
| **Testing Guide** | [owasp.org/testing-guide](https://owasp.org/www-project-web-security-testing-guide/) |

## Other OWASP Top 10 Lists

| List | URL | Description |
| :--- | :--- | :--- |
| **LLM/AI Top 10** | [llmtop10.com](https://llmtop10.com/) | Prompt injection, data leakage, insecure plugins |
| **API Security Top 10** | [owasp.org/API-Security](https://owasp.org/API-Security/) | Broken auth, BOLA, rate limiting |
| **Mobile Top 10** | [owasp.org/www-project-mobile-top-10](https://owasp.org/www-project-mobile-top-10/) | Insecure storage, weak auth |
| **Cloud-Native Top 10** | [owasp.org/cloud-native](https://owasp.org/www-project-cloud-native-application-security-top-10/) | Misconfig, secrets mgmt |
| **Serverless Top 10** | [owasp.org/serverless](https://owasp.org/www-project-serverless-top-10/) | Over-privileged functions, injection |
| **CI/CD Top 10** | [owasp.org/cicd](https://owasp.org/www-project-top-10-ci-cd-security-risks/) | Pipeline poisoning, insecure configs |
| **Kubernetes Top 10** | [owasp.org/kubernetes](https://owasp.org/www-project-kubernetes-top-ten/) | Workload security, network policies |
| **IoT Top 10** | [owasp.org/iot](https://owasp.org/www-project-internet-of-things/) | Weak passwords, insecure network, lack of updates |
| **ICS/OT Top 10** | [owasp.org/ics](https://owasp.org/www-project-operational-technology-top-10/) | Industrial control systems security |
| **DevSecOps Guidelines** | [owasp.org/devsecops](https://owasp.org/www-project-devsecops-guideline/) | Secure SDLC, SAST, DAST, SCA, secrets mgmt |
| **SAMM (Maturity Model)** | [owaspsamm.org](https://owaspsamm.org/) | Security maturity assessment for organizations |

## Cloud Security Resources

| Provider | Resource | URL |
| :--- | :--- | :--- |
| **AWS** | Well-Architected Security Pillar | [docs.aws.amazon.com/wellarchitected](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/) |
| **AWS** | Security Best Practices | [aws.amazon.com/security](https://aws.amazon.com/architecture/security-identity-compliance/) |
| **Azure** | Security Benchmark | [learn.microsoft.com/azure/security](https://learn.microsoft.com/en-us/security/benchmark/azure/) |
| **Azure** | Defender for Cloud | [learn.microsoft.com/defender](https://learn.microsoft.com/en-us/azure/defender-for-cloud/) |
| **GCP** | Security Best Practices | [cloud.google.com/security](https://cloud.google.com/security/best-practices) |
| **GCP** | Security Command Center | [cloud.google.com/security-command-center](https://cloud.google.com/security-command-center) |

## OWASP Top 10 (2025)

| # | Vulnerability | Prevention Strategy |
| :--- | :--- | :--- |
| **A01** | **[[Broken Access Control]]** | Deny by default, enforce record-level ownership, disable directory listings. |
| **A02** | **[[Security Misconfiguration]]** | Hardened configs, remove defaults, automate verification, lock down cloud settings. |
| **A03** | **[[Software Supply Chain Failures]]** | SBOM generation, verify signatures, lock dependencies, scan for malicious packages. |
| **A04** | **[[Cryptographic Failures]]** | Use modern algorithms (e.g., AES-256), encrypt data at rest/transit, manage keys securely. |
| **A05** | **[[Injection]]** | Parameterized queries (Prepared Statements), input validation, safe APIs. |
| **A06** | **[[Insecure Design]]** | Threat modeling, secure design patterns, "secure by default" architecture. |
| **A07** | **[[Authentication Failures]]** | MFA, strong password policies, rate limiting, secure session management. |
| **A08** | **[[Software & Data Integrity Failures]]** | Verify digital signatures, trusted CI/CD pipelines, signed commits. |
| **A09** | **[[Logging & Alerting Failures]]** | Centralized logging, tamper-proof storage, real-time alerting. |
| **A10** | **[[Mishandling of Exceptional Conditions]]** | Fail safe (closed), generic user errors, detailed admin logs, catch-all exceptions. |

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
