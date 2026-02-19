# Changelog

All notable changes to this project will be documented in this file.

## [0.9.5] - 2026-02-19

### Changed
- Replaced hashed share token lookup (`ShareTokenHash`/`ShareTokenPrefix`) with direct `ShareToken` index for simpler, faster share resolution.
- Added upload purpose tracking to isolate template background uploads from share files.
- New share checkbox/select options now persist per draft when opening the custom download page designer.
- Refreshed README screenshots for password and gallery share views.

### Removed
- `ShareTokenHash` and `ShareTokenPrefix` columns (migration `V0901_ShareTokenPlaintextOnly`).

## [0.9.4] - 2026-02-19

### Changed
- Updated README and AGENTS documentation.

## [0.9.3] - 2026-02-19

### Added
- Quick-share upload cancellation with immediate background cleanup of in-flight uploads.
- Image lightbox on share pages with keyboard navigation, per-file download, and prev/next browsing.
- Upload limits validation UI with per-file and total size enforcement.
- OG image generation for share links (1200x630 social preview images).
- PDF first-page image preview generation.
- Preview generation runs as dedicated Hangfire jobs on a `previews` queue.
- Adaptive share preview mode: image mosaic for image-only shares, file-by-file previews for mixed uploads.
- Pending previews return a temporary placeholder image with retry-friendly UI.
- Optional per-share download password with encrypted-at-rest ZIP storage.
- Download notification emails include IP geolocation (`City, Country`) via `ipwho.is`.
- Email templates include dark-mode-aware styling for `prefers-color-scheme`.
- Auth emails are queued and sent asynchronously via Hangfire.
- Share creation is queued in Hangfire with live SignalR progress streaming.
- Share-created success screen supports reopening the Share Ready link.
- Previous shares Details modal lists archived filenames and sizes.

### Changed
- Frontend scripts migrated from inline JS to TypeScript bundles (`src/Agora.Web/scripts/ts`).
- Share delivery and storage architecture modularized (`IShareContentStore`, `IShareExperienceRenderer`).
- Removed hosted single-page share experience in favor of adaptive preview rendering.
- Removed security review artifacts (`SECURITY.md`, `SECURITY_CLAUDE.md`, `SECURITY_CODEX.md`) after issues were resolved.

### Fixed
- Serilog console sink added for development logging.

## [0.9.2] - 2026-02-17

### Changed
- Consolidated publish profile into main `build.csando` file (removed `build.publish.csando`).
- Publish profile now builds and pushes multi-arch Docker images directly to GHCR (`ghcr.io/aduggleby/agora`).

## [0.9.1] - 2026-02-17

### Added
- User authentication with cookie-based sessions.
- Registration with email confirmation before first login.
- Forgot password and password reset flows.
- Account settings with email and password update forms (both require confirmation).
- Share-created success screen with one-click link copy.
- Previous shares list on dashboard with Details modal showing archived filenames and sizes.
- Customizable share link tokens (default: 8-character alphanumeric).
- Download page designer with configurable card position (corners, edges, centered).
- Share defaults settings page.
- New accounts default download page subtitle set to `by <account email>`.
- Signed-in downloads excluded from download totals.
- Built-in rate limiting for auth, authenticated user traffic, and share downloads.
- CSRF protection on unsafe HTTP methods (forms, fetch, and XHR).
- Login brute-force protection with temporary account lockout after repeated failures.
- Share token hashing at rest.
- Playwright end-to-end test suite (`tests/e2e`).
- Warm Craft design system with `STYLEGUIDE.md`.
- Tailwind CSS v4 theme and build workflow.
- `tmux`-based development scripts (`run-dev.sh`, `stop-dev.sh`).
- Security review reports (`SECURITY.md`, `SECURITY_CLAUDE.md`, `SECURITY_CODEX.md`).

### Fixed
- `dotnet watch` no longer triggers overlay on upload-created file changes.
- `stop-dev.sh` reliably frees dev ports and kills orphaned app processes.

## [0.9.0] - 2026-02-17

### Added
- Initial Agora ASP.NET Core 10 file sharing service implementation.
- Multi-file upload with ZIP archive creation and disk storage.
- Share links with landing page, download endpoint, and expiry handling.
- Download event recording with IP, user-agent, and timestamp metadata.
- Notification mode handling (`none`, `once`, `every_time`) with concurrency-safe `once` semantics.
- Resend-compatible email sender abstraction with configurable API base URL.
- Serilog daily rolling logs with 30-day retention.
- Dockerfile for containerized deployment.
- `build.csando` ANDO build script.
- `README.md` with TrueNAS SCALE deployment instructions.
- `AGENTS.md` with project-specific agent guidance.
