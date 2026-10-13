---
status: complete
priority: p1
issue_id: "001"
tags: [code-review, security, configuration]
dependencies: []
---

# Remove hardcoded SQL credentials

## Problem Statement

Database credentials are hardcoded in application defaults, which exposes secrets in source control and encourages insecure runtime configuration.

## Findings

- `src/Agora.Web/appsettings.json:3` contains an explicit SQL Server connection string with `User Id=sa` and password.
- `src/Agora.Web/Program.cs:56` sets the same credentialed SQL Server connection string as fallback when `ConnectionStrings:Default` is missing.
- This violates the repository rule to avoid hardcoded secrets and increases accidental credential reuse risk.

## Proposed Solutions

### Option 1: Remove all credentialed defaults (Recommended)

**Approach:** Keep `ConnectionStrings:Default` empty/non-secret in repo, require env var injection in runtime.

**Pros:**
- Eliminates secret exposure in git history.
- Aligns with container/env-only configuration model.

**Cons:**
- Local setup needs explicit configuration.

**Effort:** Small

**Risk:** Low

---

### Option 2: Use non-secret local dev defaults + user secrets

**Approach:** Keep a local-only SQLite default in repo; put SQL credentials in `dotnet user-secrets` or env vars.

**Pros:**
- Easy local onboarding.
- Keeps secrets out of tracked files.

**Cons:**
- Slightly more setup complexity.

**Effort:** Small

**Risk:** Low

## Recommended Action


## Technical Details

**Affected files:**
- `src/Agora.Web/appsettings.json:3`
- `src/Agora.Web/Program.cs:56`

## Resources

- **Review target:** current branch working tree

## Acceptance Criteria

- [ ] No credentialed connection strings remain in tracked config/code.
- [ ] Runtime configuration works via environment variables or user-secrets.
- [ ] Build and tests still pass with expected dev configuration.

## Work Log

### 2026-02-19 - Initial Review Finding

**By:** Codex

**Actions:**
- Reviewed configuration and startup diffs.
- Identified hardcoded DB credentials in both appsettings and fallback code.

**Learnings:**
- Credentials are duplicated in two locations, increasing exposure and drift risk.

## Notes

- This is a merge-blocking security/configuration issue.

### 2026-02-19 - Resolution

**By:** Codex

**Actions:**
- Implemented the agreed fix in code.
- Re-ran required validation commands (`dotnet build Agora.slnx`, `dotnet test tests/Agora.Application.Tests/Agora.Application.Tests.csproj`).

**Learnings:**
- The fix is stable under current local validation; broader e2e coverage can be run separately.
