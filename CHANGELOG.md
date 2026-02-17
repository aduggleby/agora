# Changelog

All notable changes to this project will be documented in this file.

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
