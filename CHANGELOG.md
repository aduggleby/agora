# Changelog

All notable changes to this project will be documented in this file.

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
