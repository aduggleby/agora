# AGENTS.md

## Project Identity

- Name: `Agora`
- Stack: ASP.NET Core 10, EF Core SQLite, Serilog, Docker
- Reserved ports: `18000-18099`
- Default app port: `18080`

## Agent Objectives

When working in this repository, agents should prioritize:

1. Correctness and safety for file handling, downloads, and retention.
2. Consistent namespace/project naming under `Agora.*`.
3. Predictable operations in containerized environments (single data volume + env vars).
4. Minimal, test-backed changes.

## Hard Requirements

- Keep project names and namespaces under `Agora`.
- Keep naming consistently under the `Agora` identity.
- Do not hardcode secrets.
- Keep all persisted mutable runtime data under `/app/data` when containerized.
- Ensure log retention remains daily rolling with 30-day retention.
- Preserve token-at-rest hashing behavior.

## Build/Test Commands

- `dotnet restore Agora.slnx`
- `dotnet build Agora.slnx`
- `dotnet test tests/Agora.Application.Tests/Agora.Application.Tests.csproj`
- `ando` (uses `build.csando`)

## Container Contract

The container must run with only:

- Environment variables for config
- One writable volume
  - `/app/data` (contains uploads/db/logs)

Default container port:

- `18080`

## Port Allocation

This project is assigned `18000-18099` in `~/Source/PORTS.md`.
Agents should use ports in this range for local services and examples.

## File Ownership and Layout

- `src/Agora.Web` - endpoints, startup, hosted services
- `src/Agora.Application` - models, abstractions, utility logic
- `src/Agora.Infrastructure` - persistence and concrete services
- `src/Agora.Domain` - entities
- `tests/Agora.Application.Tests` - fast unit tests
- `docs/plans` - planning artifacts
- `todos` - file-based work tracking

## UI & Design

All frontend UI follows the **Warm Craft** design system. See [`STYLEGUIDE.md`](./STYLEGUIDE.md) for the full specification including colors, typography, components, and layout patterns.

Key constraints:
- Use Tailwind CSS v4 classes from the theme defined in `src/Agora.Web/Styles/tailwind.css`
- Display font: Instrument Serif. Body font: DM Sans. No other fonts.
- Primary accent: `terra` (#C4663A). Do not introduce new accent colors.
- Build CSS with `npm run tailwind:build` in `src/Agora.Web/` after any HTML changes.
- Public share pages (`/s/{token}`) use inline CSS (not Tailwind) for self-contained rendering.

## Coding Rules

- Keep new code ASCII unless file requires Unicode.
- Prefer explicit validation for user inputs.
- Use UTC for all persisted timestamps.
- Stream file operations; avoid loading full payloads in memory.
- Keep APIs stable and additive where possible.

## Operational Rules

- Keep share cleanup behavior intact.
- Keep download event recording intact.
- Keep email notification modes intact (`none`, `once`, `every_time`).
- If modifying DB entities, update `AgoraDbContext` mapping and migration/bootstrap behavior.

## Documentation Rules

When behavior changes, update at least one of:

- `README.md`
- `AGENTS.md`
- `docs/plans/*.md` (if scope/plans are affected)

## Safe Defaults for Examples

Use these defaults in docs/examples unless user asks otherwise:

- Port: `18080`
- DB: `Data Source=/app/data/uploads/agora.db`
- Storage root: `/app/data/uploads`
- Logs: `/app/data/logs`
