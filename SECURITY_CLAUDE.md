# Security Review Report (Priority-Ordered)

Scope reviewed: auth/session, authorization, upload/download/file handling, template rendering/XSS, SQL injection surface, secrets/configuration, and dependency vulnerabilities.

## High Priority

1. Insecure transport not enforced (risk of credential/session exposure on HTTP).  
`src/Agora.Web/Program.cs:145` and `src/Agora.Web/Program.cs:50` show no HTTPS redirection/HSTS and default cookie config; `Dockerfile:19` binds HTTP only.  
Impact: if deployed without a strict TLS-terminating reverse proxy, auth cookies and credentials can be intercepted.  
Recommendation: add `UseHttpsRedirection()` + `UseHsts()` (non-dev), set cookie `SecurePolicy=Always`, and document/enforce HTTPS-only ingress.

2. Test-only E2E endpoints can become production account-takeover primitives if misconfigured.  
`src/Agora.Web/Program.cs:303`-`src/Agora.Web/Program.cs:383` exposes unauthenticated user creation and share expiry mutation when `AGORA_E2E`/`E2E:Enabled` is true.  
Impact: environment misconfiguration could allow unauthorized user creation and data tampering.  
Recommendation: compile out in production builds, or additionally require admin auth + one-time secret header + local-network restriction.

## Medium Priority

1. CSRF protections are missing on cookie-authenticated minimal API `POST` endpoints.  
Examples: `src/Agora.Web/Program.cs:841`, `src/Agora.Web/Program.cs:884`, `src/Agora.Web/Program.cs:1022`, `src/Agora.Web/Program.cs:1070`, `src/Agora.Web/Program.cs:1234`.  
Impact: cross-site request forgery against authenticated users (partially mitigated by SameSite defaults, but not a full control).  
Recommendation: enable antiforgery validation for these endpoints and send antiforgery tokens in forms/XHR.

2. No login throttling / brute-force controls.  
`src/Agora.Infrastructure/Auth/AuthService.cs:62`-`src/Agora.Infrastructure/Auth/AuthService.cs:81` performs credential checks without lockout/backoff/rate limits.  
Impact: credential stuffing and password guessing risk.  
Recommendation: add IP/user rate limiting (`AddRateLimiter`) and progressive lockout/backoff.

3. SVG uploads allowed and served from same origin as authenticated app.  
Upload allowlist includes `.svg` at `src/Agora.Web/Program.cs:3193`-`src/Agora.Web/Program.cs:3196`; served at `src/Agora.Web/Program.cs:1666`-`src/Agora.Web/Program.cs:1698`.  
Impact: potential script-capable SVG abuse depending on browser/client handling.  
Recommendation: disallow SVG for user uploads or sanitize SVG strictly; also add `X-Content-Type-Options: nosniff` and stronger CSP.

## Low Priority

1. Hardcoded dev SQL SA password committed in repo.  
`src/Agora.Web/appsettings.Development.json:3` includes `Password=AgoraDev!Passw0rd` with `TrustServerCertificate=True`.  
Impact: credential hygiene issue; risk if reused or copied.  
Recommendation: move to user-secrets/env vars; avoid SA in development workflows.

2. Generated development admin password is logged.  
`src/Agora.Web/Program.cs:125`-`src/Agora.Web/Program.cs:128`.  
Impact: sensitive credential exposure in logs (dev scope).  
Recommendation: remove password from logs; log only that user was created.

3. Upload ID path handling should be constrained to expected format.  
`src/Agora.Infrastructure/Services/ShareManager.cs:505`-`src/Agora.Infrastructure/Services/ShareManager.cs:515` uses user-supplied `uploadId` in filesystem paths without strict format validation.  
Impact: currently mitigated by metadata ownership checks, but hardening gap remains.  
Recommendation: enforce strict GUID/hex format before any path combine and verify full-path containment.

## Dependency/Supply Chain Check

- `dotnet list ... --vulnerable --include-transitive`: no known vulnerable NuGet packages.
- `npm audit` (`src/Agora.Web`, `tests/e2e`): no reported vulnerabilities.

## Notable Strong Controls Already Present

- Password hashing uses PBKDF2 with per-password salt and constant-time verify (`src/Agora.Application/Utilities/PasswordHasher.cs`).
- Share tokens are hashed at rest (`src/Agora.Application/Utilities/TokenCodec.cs`).
- File ownership checks exist for staged uploads and draft association (`src/Agora.Infrastructure/Services/ShareManager.cs:538`-`src/Agora.Infrastructure/Services/ShareManager.cs:547`).

## Assumptions

- Severity for transport and CSRF findings assumes internet-accessible deployment and standard browser behavior.
- If TLS and ingress security headers are enforced externally, transport risk is reduced but should still be codified in-app for defense in depth.
