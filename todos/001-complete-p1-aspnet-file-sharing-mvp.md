---
status: complete
priority: p1
issue_id: "001"
tags: [aspnet, file-sharing, mvp]
dependencies: []
---

## Problem Statement
Implement MVP of the planned ASP.NET file sharing service.

## Findings
Empty repo; full scaffold required.

## Proposed Solutions
- Build minimal vertical-slice monolith with EF Core + Razor Pages.

## Recommended Action
Scaffold solution, implement upload/share/download, expiry checks, Serilog, and tests.

## Acceptance Criteria
- [x] Solution scaffolding exists and builds
- [x] Upload creates zip and share URL
- [x] Landing page renders share metadata and message
- [x] Download streams zip and records download event
- [x] Notify mode once/every_time behavior implemented safely
- [x] Serilog rolling daily with 30-day retention
- [x] Basic tests pass

## Work Log
### 2026-02-17 - Kickoff
**By:** Codex

**Actions:**
- Created todo and started execution.

**Learnings:**
- Repository starts empty.

### 2026-02-17 - MVP Implementation
**By:** Codex

**Actions:**
- Scaffolded .NET 10 solution and four project layers.
- Implemented upload, ZIP storage, token hash lookup, landing page, and download endpoint.
- Implemented download event persistence, once/every_time email decision logic, and cleanup hosted service.
- Added Serilog rolling-file logging (30-day retention) and app configuration.
- Added unit tests for archive naming and token hashing.
- Verified with `dotnet build`, `dotnet test`, and manual smoke test using `curl`.

**Learnings:**
- `Results.File` with a path can be treated as virtual file in this stack; returning a stream avoids that issue.
