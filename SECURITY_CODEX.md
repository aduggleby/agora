# Security Review Report (Codex)

Date: 2026-02-17  
Repository: `Agora` (`/home/alex/Source/agora`)

## Executive Summary

Overall risk is **High**. The review found **2 critical**, **3 high**, and **4 medium** findings. As of 0.9.1, rate limiting (#5) and CSRF (#6) are fixed. The most significant remaining issues are plaintext share token storage, unauthenticated E2E endpoints when enabled, and sensitive data leakage through logs.

## Risk Matrix

- Critical: 2
- High: 3 (1 fixed in 0.9.1)
- Medium: 4 (1 fixed in 0.9.1)
- Low: 0

## Detailed Findings (By Priority)

### Critical

1. Plaintext share tokens stored at rest
- Description: Share tokens are persisted directly and are recoverable from the database.
- Evidence:
  - `src/Agora.Domain/Entities/Share.cs:7`
  - `src/Agora.Infrastructure/Services/ShareManager.cs:121`
  - `src/Agora.Infrastructure/Services/ShareManager.cs:264`
- Impact: Database read compromise exposes all active share links immediately.
- Recommendation: Stop persisting plaintext token material; store only hash/prefix and redesign copy/reveal flow to avoid long-term token recoverability.

2. Unauthenticated E2E mutation endpoints (when E2E mode is enabled)
- Description: Test endpoints can create users and alter share expiry without authentication.
- Evidence:
  - `src/Agora.Web/Program.cs:305`
  - `src/Agora.Web/Program.cs:359`
- Impact: If enabled in a reachable environment, attacker can create accounts and manipulate share lifecycle.
- Recommendation: Remove from production build/runtime or gate with strict secret header + network allowlist + explicit hard environment checks.

### High

3. Sensitive credential/token leakage in logs
- Description:
  - Development admin password is logged at startup.
  - Request logs include tokenized URL paths.
- Evidence:
  - `src/Agora.Web/Program.cs:126`
  - `src/Agora.Web/logs/agora-20260217.log:91`
  - `src/Agora.Web/logs/agora-20260217.log:156`
- Impact: Anyone with log access can reuse credentials/tokens.
- Recommendation: Remove password logging entirely and sanitize/mask token-bearing paths in request logs.

4. Share token policy allows very short public tokens
- Description: Server accepts tokens with length 3..64 and alphanumeric only.
- Evidence:
  - `src/Agora.Web/Program.cs:1750`
  - `src/Agora.Web/Pages/Shares/New.cshtml:62`
- Impact: Brute-force/enumeration risk increases significantly for short tokens.
- Recommendation: Enforce stronger minimum length (for example 12+) server-side; avoid user-selected short custom tokens.

5. ~~Missing anti-automation/rate limiting on sensitive endpoints~~
**Fixed in 0.9.1** — built-in rate limiting for auth endpoints (10 req/min per IP), authenticated requests (120 req/min per account), and download endpoint (20 req/min per token+IP). Temporary account lockout after repeated login failures.

### Medium

6. ~~CSRF protections not explicit for cookie-authenticated Minimal APIs~~
**Fixed in 0.9.1** — antiforgery validation on unsafe HTTP methods (forms, fetch, and XHR).

7. Missing explicit HTTPS and security header hardening
- Description: No explicit HTTPS redirection/HSTS/security header middleware observed.
- Evidence:
  - `src/Agora.Web/Program.cs`
- Impact: Weaker browser/network-layer protections.
- Recommendation: Enable `UseHttpsRedirection`, `UseHsts` (prod), and baseline headers (CSP, X-Content-Type-Options, frame protections, referrer policy).

8. Weak registration password policy
- Description: Registration path checks only for non-empty password.
- Evidence:
  - `src/Agora.Infrastructure/Auth/AuthService.cs:18`
- Impact: Weak user passwords can be created.
- Recommendation: Enforce minimum complexity/length at registration (align with or exceed change-password policy).

9. Hardcoded development DB credential in tracked config
- Description: Development SQL credentials are committed in config.
- Evidence:
  - `src/Agora.Web/appsettings.Development.json:3`
- Impact: Credential reuse and secret sprawl risk.
- Recommendation: Move secrets to user-secrets/environment variables and rotate if reused.

## Validated Areas (No Immediate Vulnerability Found)

- SQL injection: No user-controlled raw SQL execution identified in request paths.
- Dependency vulnerabilities:
  - `dotnet list Agora.slnx package --vulnerable --include-transitive`: no known vulnerabilities reported.
  - `npm audit --omit=dev` in `src/Agora.Web`: none.
  - `npm audit --omit=dev` in `tests/e2e`: none.
- XSS baseline: Predominant Razor encoding and explicit HTML encoding helper usage in dynamic legacy rendering paths.

## OWASP Top 10 Mapping Snapshot

- A01 Broken Access Control: **Fail** (E2E endpoints if enabled)
- A02 Cryptographic Failures: **Fail** (plaintext share tokens)
- A03 Injection: **Pass (current scan)**
- A04 Insecure Design: **Partial** (short token policy; throttling fixed in 0.9.1)
- A05 Security Misconfiguration: **Fail** (sensitive logging, missing explicit hardening)
- A06 Vulnerable Components: **Pass (tooling results)**
- A07 Identification and Authentication Failures: **Partial** (weak registration password policy)
- A08 Software and Data Integrity Failures: **No major finding in this pass**
- A09 Security Logging and Monitoring Failures: **Fail** (token/password exposure in logs)
- A10 SSRF: **No major finding in this pass**

## Remediation Roadmap

1. Remove plaintext token storage and eliminate credential/token log exposure.
2. Lock down/remove E2E endpoints from non-test runtime contexts.
3. Strengthen token/password policies. ~~Add rate limiting.~~ (Fixed in 0.9.1)
4. ~~Add CSRF protections for cookie-authenticated mutating routes.~~ (Fixed in 0.9.1)
5. Add explicit HTTPS + security-header baseline and externalize development secrets.

## Assumptions / Open Questions

1. Whether `AGORA_E2E` is ever enabled outside isolated test environments.
2. Who has read access to runtime logs and whether logs are exported centrally.
3. Whether TLS is guaranteed upstream in all deployment environments.
