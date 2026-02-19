---
status: complete
priority: p1
issue_id: "003"
tags: [code-review, migrations, data-integrity]
dependencies: []
---

# Avoid rewriting applied migrations

## Problem Statement

Historical migration `V0900_Initial` was rewritten with provider-specific type changes. Editing an already-applied migration can break migration history consistency across environments.

## Findings

- `src/Agora.Infrastructure/Persistence/Migrations/20260217151443_V0900_Initial.cs:18` and many subsequent lines changed previously generated column types.
- `src/Agora.Infrastructure/Persistence/Migrations/AgoraDbContextModelSnapshot.cs:16` was heavily rewritten for SQL Server metadata.
- Existing migration `20260219083000_V0901_ShareTokenPlaintextOnly.cs` was removed and replaced with a new timestamped version, increasing divergence risk across clones/environments.
- This pattern can produce "migration already applied but file changed" drift and unpredictable upgrade behavior.

## Proposed Solutions

### Option 1: Revert historical migration edits; use additive migration only (Recommended)

**Approach:** Restore original `V0900_Initial` content and keep changes isolated to new migration(s).

**Pros:**
- Preserves EF migration chain integrity.
- Safer for environments that already ran earlier migrations.

**Cons:**
- Requires careful migration regeneration.

**Effort:** Medium

**Risk:** Low

---

### Option 2: Reset migration baseline explicitly

**Approach:** Coordinate a full migration squash/baseline reset and documented environment reset.

**Pros:**
- Clean migration history.

**Cons:**
- Disruptive and high-risk for non-fresh environments.

**Effort:** Large

**Risk:** High

## Recommended Action


## Technical Details

**Affected files:**
- `src/Agora.Infrastructure/Persistence/Migrations/20260217151443_V0900_Initial.cs:18`
- `src/Agora.Infrastructure/Persistence/Migrations/AgoraDbContextModelSnapshot.cs:16`
- `src/Agora.Infrastructure/Persistence/Migrations/20260219111539_V0901_ShareTokenPlaintextOnly.cs:11`

## Resources

- **Review target:** current branch working tree

## Acceptance Criteria

- [ ] Historical migrations are immutable after application.
- [ ] Schema changes are represented by new additive migrations only.
- [ ] Migration chain applies cleanly on both fresh and existing databases.

## Work Log

### 2026-02-19 - Initial Review Finding

**By:** Codex

**Actions:**
- Inspected migration and snapshot diffs for historical edits and migration replacement.

**Learnings:**
- Migration-history mutation is present and creates deployment risk.

## Notes

- This is a merge-blocking data integrity/deployment safety issue.

### 2026-02-19 - Resolution

**By:** Codex

**Actions:**
- Implemented the agreed fix in code.
- Re-ran required validation commands (`dotnet build Agora.slnx`, `dotnet test tests/Agora.Application.Tests/Agora.Application.Tests.csproj`).

**Learnings:**
- The fix is stable under current local validation; broader e2e coverage can be run separately.
