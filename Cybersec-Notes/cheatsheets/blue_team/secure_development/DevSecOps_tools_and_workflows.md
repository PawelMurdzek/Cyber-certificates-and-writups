# DevSecOps Tools & Workflows

## Secure Git Workflows

### 1. Branch Protection Rules
Enforce these settings on `main` and `develop` branches:
- **Require pull request reviews before merging** (at least 1-2 reviewers).
- **Require status checks to pass** (CI/CD pipelines, tests, security scans).
- **Require signed commits** (verify GPG signatures).
- **Prevent force pushes** (to maintain history integrity).

### 2. Pre-Commit Hooks
Catch issues *before* code leaves the developer's machine using [pre-commit](https://pre-commit.com/).

```yaml
# .pre-commit-config.yaml example
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: check-yaml
      - id: detect-private-key  # Basic secret detection
```

### 3. Signed Commits
Configure Git to sign commits with GPG.

```bash
# Generate key
gpg --full-generate-key

# Configure Git
git config --global user.signingkey <KEY_ID>
git config --global commit.gpgsign true
```

---

## Platform Specifics: GitHub vs GitLab

| Feature | GitHub | GitLab |
| :--- | :--- | :--- |
| **CI/CD Config** | `.github/workflows/*.yaml` | `.gitlab-ci.yml` |
| **Branch Rules** | Settings > Branches > Protection rules | Settings > Repository > Protected branches |
| **Auto-Dependency Updates** | Dependabot | GitLab Dependency Scanning / Renovate |
| **Native SAST** | CodeQL (GitHub Advanced Security) | GitLab SAST (Semgrep based) |
| **Native Secrets** | Secret Scanning | Secret Detection |

---

## Tool Setup Guide

### 1. Secrets Management (Detection)
Prevent hardcoded credentials from reaching the repo.

| Tool | Description | Setup/Usage |
| :--- | :--- | :--- |
| **Gitleaks** | Fast, light-weight secret detector. | `gitleaks detect --source . -v` |
| **Trivy** | All-in-one scanner (secrets, vulns). | `trivy fs . --scanners secret` |

**GitHub Actions (TruffleHog):**
```yaml
- name: TruffleHog OSS
  uses: trufflesecurity/trufflehog@main
  with:
    base: "${{ github.event.repository.default_branch }}"
    head: HEAD
```

**GitLab CI (TruffleHog):**
```yaml
trufflehog:
  stage: test
  image: trufflesecurity/trufflehog:latest
  script:
    - trufflehog git file://. --since-commit HEAD
```

### 2. SCA (Software Composition Analysis)
Identify vulnerabilities in open-source dependencies.

| Tool | Description |
| :--- | :--- |
| **Trivy** | Universal scanner. Works well in both CI systems. |
| **Renovate** | Detailed dependency updates. Good alternative to Dependabot for GitLab. |
| **Dependabot** | Native to GitHub. Can be run on GitLab via script but Renovate is preferred. |

### 3. SAST (Static Application Security Testing)

**Semgrep Analysis:**

**GitHub Actions:**
```yaml
- name: Semgrep
  run: pip install semgrep && semgrep scan --config=auto --error
```

**GitLab CI:**
```yaml
semgrep:
  stage: test
  image: returntocorp/semgrep
  script:
    - semgrep scan --config=auto --error
```

### 4. DAST (Dynamic Application Security Testing)

**OWASP ZAP Baseline:**

**GitHub Actions:**
```yaml
- name: ZAP Scan
  uses: zaproxy/action-baseline@v0.7.0
  with:
    target: 'https://staging.example.com'
```

**GitLab CI:**
```yaml
zap_scan:
  stage: test
  image: owasp/zap2docker-stable
  script:
    - zap-baseline.py -t https://staging.example.com
```

---

## Secure SDLC Integration Pipeline

A typical DevSecOps pipeline stages:

1.  **IDE/Local**:
    *   Linting
    *   Pre-commit hooks (Secret check, formatting)
2.  **Commit/Push**:
    *   Trigger CI Pipeline
3.  **Build Stage**:
    *   **SCA**: Check dependencies (`npm audit`, `trivy`)
    *   **SAST**: Scan code (`semgrep`, `sonar-scanner`)
    *   **Secret Scan**: Scan history (`gitleaks`)
4.  **Test/Deploy to Staging**:
    *   Deploy app
    *   **DAST**: Run active scan against staging URL (`zap-baseline`)
5.  **Review**:
    *   Block merge if Critical/High severity found
    *   Manual Code Review
6.  **Deploy to Prod**:
    *   Continuous Monitoring
