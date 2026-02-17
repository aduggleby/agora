# Security Priorities (Merged: Claude + Codex)

Date: 2026-02-17

| Priority | Fix Item | Why It’s High Priority | Evidence | Source |
|---|---|---|---|---|
| Critical | Stop storing plaintext share tokens | DB read access currently reveals valid download links directly. | `src/Agora.Domain/Entities/Share.cs:7`, `src/Agora.Infrastructure/Services/ShareManager.cs:121` | Codex |
| Critical | Lock down/remove E2E mutation endpoints | If E2E mode is enabled outside isolated test envs, unauthenticated callers can create users and modify share expiry. | `src/Agora.Web/Program.cs:305`, `src/Agora.Web/Program.cs:359` | Claude + Codex |
| High | Enforce HTTPS + secure cookie posture | Prevent credential/session exposure and downgrade risk if deployment is misconfigured. | `src/Agora.Web/Program.cs:51` (cookie config), no explicit `UseHttpsRedirection`/`UseHsts` | Claude + Codex |
| High | Remove sensitive secrets/tokens from logs | Logged passwords/tokens can be replayed by anyone with log access. | `src/Agora.Web/Program.cs:126`, `src/Agora.Web/logs/agora-20260217.log:91` | Codex (+ Claude for password logging) |
| High | Raise token strength + add rate limiting | Short token acceptance plus no throttling increases brute-force/enumeration risk. | `src/Agora.Web/Program.cs:1750`, `src/Agora.Web/Pages/Shares/New.cshtml:62`, no `AddRateLimiter` in `src/Agora.Web/Program.cs` | Codex |
| High | Add CSRF protection for cookie-authenticated POST APIs | Prevent cross-site state-changing requests against authenticated sessions. | POST APIs in `src/Agora.Web/Program.cs:884`, `src/Agora.Web/Program.cs:1070`, `src/Agora.Web/Program.cs:1234` | Claude + Codex |
| High | Add login brute-force protections | Reduces credential stuffing/password guessing impact. | `src/Agora.Infrastructure/Auth/AuthService.cs:62` | Claude + Codex |
