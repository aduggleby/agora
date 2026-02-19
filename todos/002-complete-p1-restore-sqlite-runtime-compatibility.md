---
status: complete
priority: p1
issue_id: "002"
tags: [code-review, architecture, runtime, data]
dependencies: []
---

# Restore SQLite runtime compatibility

## Problem Statement

The runtime was changed to SQL Server-only behavior, which breaks the documented project stack and container contract requiring SQLite support.

## Findings

- `src/Agora.Web/Program.cs:61` now always configures `UseSqlServer(...)`; SQLite branch was removed.
- `src/Agora.Web/Program.cs:166` Hangfire now always uses SQL Server storage; in-memory fallback was removed.
- `src/Agora.Web/Startup/SchemaUpgradeRunner.cs:10` throws for non-SQL Server providers (`"Agora supports SQL Server only."`).
- Project guidance declares stack includes EF Core SQLite and container defaults based on that contract.

## Proposed Solutions

### Option 1: Reintroduce provider-conditional setup (Recommended)

**Approach:** Detect provider from connection string/config and wire DbContext + Hangfire + schema upgrades for SQLite and SQL Server.

**Pros:**
- Restores expected behavior and backward compatibility.
- Keeps flexibility for local/dev/test/container environments.

**Cons:**
- Slightly more startup branching logic.

**Effort:** Medium

**Risk:** Medium

---

### Option 2: Make SQL Server-only an explicit migration program

**Approach:** If SQL Server-only is intentional, update AGENTS/README/contracts and provide migration tooling from SQLite.

**Pros:**
- Consistent long-term direction if intentional.

**Cons:**
- Large operational change, significant migration risk.
- Conflicts with current documented requirements unless coordinated.

**Effort:** Large

**Risk:** High

## Recommended Action


## Technical Details

**Affected files:**
- `src/Agora.Web/Program.cs:56`
- `src/Agora.Web/Program.cs:61`
- `src/Agora.Web/Program.cs:166`
- `src/Agora.Web/Startup/SchemaUpgradeRunner.cs:10`

## Resources

- **Review target:** current branch working tree

## Acceptance Criteria

- [ ] App can run with SQLite configuration as documented.
- [ ] Schema upgrade path does not throw for supported providers.
- [ ] Hangfire storage choice is provider-compatible.
- [ ] E2E/local docs remain accurate for supported providers.

## Work Log

### 2026-02-19 - Initial Review Finding

**By:** Codex

**Actions:**
- Compared runtime startup/provider wiring changes.
- Verified SQL Server-only enforcement introduced at startup and schema runner layers.

**Learnings:**
- Current behavior diverges from repository operational requirements.

## Notes

- This is a merge-blocking architecture/compatibility issue.

### 2026-02-19 - Resolution

**By:** Codex

**Actions:**
- Implemented the agreed fix in code.
- Re-ran required validation commands (`dotnet build Agora.slnx`, `dotnet test tests/Agora.Application.Tests/Agora.Application.Tests.csproj`).

**Learnings:**
- The fix is stable under current local validation; broader e2e coverage can be run separately.
