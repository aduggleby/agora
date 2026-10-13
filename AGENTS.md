# AGENTS.md

## Project Identity

- Name: `Agora`
- Stack: ASP.NET Core 10, EF Core (SQL Server or PostgreSQL), Hangfire, Serilog, Docker
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
- Logs: daily rolling file plus stdout; retention configurable (`Agora__Logging__File__RetainedDays`), default 30 days.
- Share tokens are stored and queried in plaintext via `ShareToken` (indexed). Do not reintroduce hashing without an explicit request.
- Never hand-author EF migration files. Create/remove migrations only via `dotnet ef` tooling.
- Two migration sets must stay in sync: SQL Server (`AgoraDbContext`, `Migrations/`) and PostgreSQL (`PostgresAgoraDbContext`, `Migrations/Postgres/`). Add migrations with `scripts/add-migration.sh <Name>`, which runs `dotnet ef migrations add` for both contexts.
- SQLite must not be used for app runtime or e2e. Use SQL Server or PostgreSQL (`Database__Provider`). SQLite in-memory is allowed only in fast unit tests.
- Store and query emails lower-cased (`EmailAddress.Normalize`); PostgreSQL comparisons are case-sensitive.
- Persist only UTC `DateTime` values (`DateTimeKind.Utc`); Npgsql rejects other kinds for `timestamptz`.
- Share/upload token lookups are exact-match: case-sensitive on PostgreSQL, case-insensitive on default SQL Server collations. Do not rely on either behaviour.
- Durable content (share files, archives, backgrounds, previews) is read and written only through `IObjectStore` (`Storage__Provider=FileSystem|S3`). Never use `File.*`/`Directory.*` on durable paths, and never build durable paths from `StorageRoot`. Keys are relative, forward-slash paths validated by `ObjectKey`; `DeletePrefixAsync` takes only prefixes with at least two segments and a trailing `/`.
- Local `StorageRoot` is scratch only: staged uploads, drafts, share-create status, preview `.lock`/`.failed` markers and `StorageRoot/tmp` (`ScratchFiles`). Build archives locally, then upload; track every uploaded key and delete them if share creation fails.
- Large temp files go under `StorageRoot/tmp` (never the system `/tmp`, which may be a small tmpfs in hardened containers). Startup sets `ASPNETCORE_TEMP` to `StorageRoot/tmp/aspnet` unless it is set explicitly.

## Build/Test Commands

- Build system: `Ando` (https://andobuild.com/llms.txt)
- `dotnet restore Agora.slnx`
- `dotnet build Agora.slnx`
- `dotnet test tests/Agora.Application.Tests/Agora.Application.Tests.csproj` (PostgreSQL and MinIO tests use Testcontainers and skip without Docker; set `AGORA_REQUIRE_POSTGRES_TESTS=1` / `AGORA_REQUIRE_S3_TESTS=1` to make that a failure)
- Opt-in real-bucket smoke test: set `AGORA_S3_LIVE_BUCKET`, `AGORA_S3_LIVE_ENDPOINT`, `AGORA_S3_LIVE_REGION` (optional `AGORA_S3_LIVE_FORCE_PATH_STYLE`, default `false`) plus `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, then `dotnet test --filter LiveS3`. It works under a unique `agora-smoke/<guid>/` prefix and leaves it empty.
- E2E: `cd tests/e2e && npx playwright test` with `PLAYWRIGHT_E2E_DB=sqlserver|postgres` and `PLAYWRIGHT_E2E_STORAGE=filesystem|s3` (scripts `test:sqlserver`, `test:postgres`, `test:postgres-s3`, `test:all`). The s3 leg runs MinIO and fails teardown if durable content landed on local disk.
- `ando` (uses `build.csando`)

## Container Contract

The container must run with only:

- Environment variables for config
- One writable volume
  - `/app/data` (contains scratch: staged uploads, drafts, `uploads/tmp`; DataProtection keys; logs; and, with `Storage__Provider=FileSystem`, the durable content)
- Optional object storage: `Storage__Provider=S3` with `Storage__S3__*` (durable content in the bucket; `/app/data` still needs ≈3× the largest share × concurrent creations for scratch)
- Health endpoints: `GET /live` (process up) and `GET /ready` (database and, in S3 mode, bucket reachable)
- `Agora__PublicBaseUrl` is required outside `Development`/`E2E` (startup fails without it); links that leave the browser are never built from the request host. `Agora__TrustedProxies` lists the reverse proxies whose `X-Forwarded-*` headers are honoured (loopback only when empty).

Default container port:

- `18080`

## Port Allocation

This project is assigned `18000-18099` in `~/Source/PORTS.md`.
Agents should use ports in this range for local services and examples.

E2E defaults:
- Web app (Playwright): `18090`
- Dedicated E2E SQL Server container: `mcr.microsoft.com/mssql/server:2022-latest` on `18091`
- Dedicated E2E PostgreSQL container: `postgres:17` on `18092`
- Dedicated E2E MinIO container (`PLAYWRIGHT_E2E_STORAGE=s3`): `quay.io/minio/minio` on `18093`, bucket `agora-e2e`
- Dedicated E2E database: `agora_e2e`

## File Ownership and Layout

- `src/Agora.Web` - endpoints, startup, hosted services, Razor pages, browser scripts
- `src/Agora.Application` - models, abstractions, utility logic
- `src/Agora.Infrastructure` - persistence and concrete services
- `src/Agora.Domain` - entities
- `tests/Agora.Application.Tests` - fast unit tests
- `tests/e2e` - end-to-end browser tests
- `docs/plans` - planning artifacts
- `todos` - file-based work tracking

## UI & Design

All frontend UI follows the **Warm Craft** design system. See [`docs/STYLEGUIDE.md`](./docs/STYLEGUIDE.md) for the full specification including colors, typography, components, and layout patterns.

Key constraints:
- Use Tailwind CSS v4 classes from the theme defined in `src/Agora.Web/Styles/tailwind.css`
- Display font: Instrument Serif. Body font: DM Sans. No other fonts.
- Primary accent: `terra` (#C4663A). Do not introduce new accent colors.
- Build CSS with `npm run tailwind:build` in `src/Agora.Web/` after any HTML changes.
- Public share pages (`/s/{token}`) use inline CSS (not Tailwind) for self-contained rendering.
- Any disabled button must include a tooltip (for example `title`) explaining why the button is disabled.

## Coding Rules

General:
- Keep new code ASCII unless file requires Unicode.
- Prefer explicit validation for user inputs.
- Use UTC for all persisted timestamps.
- Display all user-facing date/time values in the browser's local timezone.
- Stream file operations; avoid loading full payloads in memory.
- Keep APIs stable and additive where possible.
- Prefer small, focused methods and explicit naming over clever abstractions.

C# and .NET:
- Prefer async APIs end-to-end for I/O paths.
- Pass `CancellationToken` through async call chains where available.
- Validate boundary inputs at endpoint/service edges.
- Keep domain logic in `Agora.Application`/`Agora.Infrastructure`, not in Razor views.
- Avoid static mutable state in web/runtime code.
- Keep structured logging fields stable and meaningful.

TypeScript:
- Author source under `src/Agora.Web/scripts/ts` and treat `src/Agora.Web/wwwroot/js` as build output.
- Prefer strict typing; avoid `any` unless unavoidable and locally justified.
- Model wire data with explicit interfaces/types.
- Keep DOM access defensive (`querySelector` null checks) and fail-safe.
- Prefer pure helper functions for formatting/transforms.
- Keep browser code framework-light and dependency-minimal.

Alpine.js:
- Use Alpine for local interaction state only, not app-wide state management.
- Keep `x-data` scopes small and component-specific.
- Prefer `x-on` handlers that call named methods over large inline expressions.
- Use `x-cloak` for hidden-until-ready UI to avoid flicker.
- Keep server as source of truth for security-sensitive decisions.
- Do not store secrets or trusted authorization state in client-side Alpine state.

Razor/HTML:
- Keep markup accessible: semantic structure, labels for inputs, and keyboard-operable controls.
- Use `aria-*` only when native semantics are insufficient.
- Keep inline scripts/styles minimal except where explicitly required (for example public share page portability).
- Avoid duplicating formatting rules in multiple views; centralize when practical.

CSS/Tailwind:
- Prefer design tokens and existing utilities over one-off values.
- Keep utility class lists readable and consistent with nearby patterns.
- Avoid introducing new theme colors/fonts without design-system updates.

## Testing & Validation Rules

- For backend changes, run at least `dotnet build Agora.slnx` and targeted tests.
- For frontend behavior changes, run relevant e2e specs under `tests/e2e` when feasible.
- If changing TypeScript sources, ensure generated JS artifacts are updated when the repo expects committed outputs.
- Add or update tests for behavior changes where practical.
- If tests are skipped, explicitly document what was not run and why.

## Security & Data Handling

- Never log secrets, raw passwords, or token material.
- Keep password verification flows unchanged unless explicitly requested.
- Validate uploaded file metadata and paths defensively.
- Preserve path traversal protections on all file read/write operations.
- Keep retention and cleanup behavior predictable and idempotent.

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

If the user asks to add or change something in `CLAUDE.md`, ask for confirmation whether they meant `AGENTS.md` before applying the change.

## Dev Log Locations

- App runtime output (tmux app pane): `.dev/agora-web.log`
- Tailwind watch output (tmux tailwind pane): `.dev/tailwind.log`
- Serilog rolling logs: `logs/agora-YYYYMMDD.log`
- Dev email sink files: `emails/`

Quick checks:

- `tail -f .dev/agora-web.log`
- `tail -f .dev/tailwind.log`
- `tail -f logs/agora-$(date +%Y%m%d).log`
- `ls -la emails`

## Safe Defaults for Examples

Use these defaults in docs/examples unless user asks otherwise:

- Port: `18080`
- DB: `Server=<sql-server-host>,1433;Database=agora;User Id=sa;Password=<password>;Encrypt=True;TrustServerCertificate=True`
- Storage root: `/app/data/uploads`
- Logs: `/app/data/logs`

## Local Claude Compatibility

- A global `~/.claude/CLAUDE.MD` file was not found in this environment during this update.
- If that file is later added, mirror relevant persistent guidance here or reference it from this section.
