---
title: feat: Build ASP.NET file sharing service with expiring links and notifications
type: feat
date: 2026-02-17
---

# feat: Build ASP.NET file sharing service with expiring links and notifications

## Overview

Build an ASP.NET Core 10 file sharing service where uploaders submit one or more files, the server creates a ZIP archive on disk, and returns a shareable URL. Recipients land on a customizable download page before downloading. Uploaders can set expiry (`date` or `indefinite`) and configure download notification emails (`once` or `every time`) containing recipient IP, browser metadata, and timestamp.

## Problem Statement

Teams need a controlled way to share files externally with:
- Simple recipient UX (download page + download button)
- Expiration controls
- Audit visibility via download notifications
- Customizable branding/page content

Current state: no existing implementation in this repository.

## Stakeholders

- End users (uploaders): upload files, configure sharing, track downloads
- End users (recipients): view download page and download file
- Operations: storage growth, retention cleanup, logs
- Developers: maintainability, secure upload/download flow, extensibility

## Proposed Solution

Create a monolithic ASP.NET Core 10 web app (MVC or Razor Pages + minimal API endpoints) with:
- Disk-backed archive storage
- Relational metadata store (SQLite for local dev, PostgreSQL for production)
- Signed random share tokens for retrieval
- Background cleanup job for expired shares/files
- Serilog file logging with daily rolling and 30-day retention
- Email integration through Resend-compatible client (`ApiUrl` configurable)

## SpecFlow Analysis

### User Flow Overview

1. Uploader creates share
- Enters email, optional message, upload files, optional custom filename, expiry mode, notification mode.
- Optionally customizes page fields per-upload or uses account defaults.
- System validates files, builds ZIP, persists metadata, returns share URL.

2. Recipient opens share URL
- Lands on custom page with title, heading, description, file details, and download button.
- If active and allowed, recipient downloads ZIP.
- System records download event and optionally sends uploader notification.

3. Expiry and cleanup
- Expired shares become non-downloadable.
- Background job marks expired and removes ZIP files from disk.

### Flow Permutations Matrix

| Flow | Variant | Expected Behavior |
|---|---|---|
| Upload | Single file, no filename override | ZIP name defaults to uploaded file basename |
| Upload | Multi-file, no filename override | ZIP name uses generated share-safe fallback |
| Upload | Filename override provided | ZIP name uses sanitized override |
| Expiry | Date selected | Download blocked after exact cutoff (UTC) |
| Expiry | Indefinite | No automatic expiry cutoff |
| Notify | Once | Email only for first successful download |
| Notify | Every time | Email per successful download |
| Page customization | Account default only | Share renders account template |
| Page customization | Per-upload override | Share renders override template |

### Missing Elements and Gaps (addressed in this plan)

- File size and count limits were unspecified.
- Allowed file extensions/MIME policy was unspecified.
- Download behavior near expiry boundary was unspecified.
- Deletion semantics for indefinite files were unspecified.
- Abuse controls (rate limiting, token brute force mitigation) were unspecified.
- Email failure behavior was unspecified.
- IP storage/privacy/retention policy was unspecified.

### Critical Questions Requiring Clarification

1. Critical: What are max upload size, max files per upload, and per-file size limits?
- Why: impacts request pipeline configuration, memory/disk safety, and UX errors.
- Default assumption: 1 GB total, 20 files, 250 MB per file.

2. Critical: Should links be unauthenticated bearer-style only, or optionally password-protected?
- Why: materially impacts threat model.
- Default assumption: bearer link only in v1.

3. Important: What should happen if ZIP generation fails mid-upload?
- Why: cleanup and user messaging.
- Default assumption: rollback DB record and delete temp files.

4. Important: Do we need malware scanning before archive publication?
- Why: security/compliance depending on environment.
- Default assumption: not in MVP; add extension point.

5. Important: What is download-event retention period (PII: IP + user agent)?
- Why: privacy/legal requirements.
- Default assumption: 90 days configurable.

## Technical Approach

### Architecture

- `src/Agora.Web/`
- `src/Agora.Application/`
- `src/Agora.Infrastructure/`
- `src/Agora.Domain/`
- `tests/Agora.*.Tests/`

Core components:
- Upload controller/page + service orchestrator
- ZIP builder service (streaming to temp file, then atomic move)
- Disk storage service
- Share retrieval and authorization service (token + expiry checks)
- Download event logger + notification dispatcher
- Background cleanup hosted service
- Custom page rendering service (account defaults + per-share override precedence)

### Data Model (ERD)

```mermaid
erDiagram
    ACCOUNT ||--o{ SHARE : creates
    ACCOUNT ||--o| PAGE_TEMPLATE : owns_default
    SHARE ||--o{ SHARE_FILE : contains
    SHARE ||--o{ DOWNLOAD_EVENT : records

    ACCOUNT {
      uuid id PK
      string email
      datetime created_at
    }

    PAGE_TEMPLATE {
      uuid id PK
      uuid account_id FK
      string title
      string heading
      text description
      string background_image_url
      datetime updated_at
    }

    SHARE {
      uuid id PK
      uuid account_id FK
      uuid page_template_id FK nullable
      string share_token_hash UNIQUE
      string share_token_prefix
      string zip_display_name
      string zip_disk_path
      bigint zip_size_bytes
      text uploader_message nullable
      string notify_mode "none|once|every_time"
      datetime expires_at_utc nullable
      datetime first_downloaded_at_utc nullable
      datetime created_at_utc
      datetime deleted_at_utc nullable
    }

    SHARE_FILE {
      uuid id PK
      uuid share_id FK
      string original_filename
      bigint original_size_bytes
      string detected_content_type
    }

    DOWNLOAD_EVENT {
      uuid id PK
      uuid share_id FK
      string ip_address
      text user_agent
      text browser_metadata_json
      datetime downloaded_at_utc
      boolean notification_sent
      string notification_error nullable
    }
```

### Storage Layout

- `storage/uploads/tmp/{guid}/` for transient multipart write
- `storage/zips/{yyyy}/{MM}/{share-id}.zip` for published archive
- Never trust client filenames for paths; sanitize and normalize
- Persist only relative storage key in DB, not absolute host path

### API and UI Flows

1. Upload POST (`src/Agora.Web/Features/Shares/CreateShareEndpoint.cs`)
- Validate files + options.
- Determine ZIP filename rule:
  - If filename override provided: sanitized value + `.zip` if missing.
  - Else if one file: basename(single file) + `.zip`.
  - Else: `files-{yyyyMMdd-HHmmss}.zip`.
- Create ZIP on disk.
- Persist share + file metadata.
- Return `shareUrl`.

2. Download page GET (`src/Agora.Web/Features/Shares/ViewSharePage.cshtml`)
- Validate token and expiry.
- Render page template fields (share override > account default > system default).
- Show file summary, uploader message, download CTA.

3. Download POST/GET (`src/Agora.Web/Features/Shares/DownloadShareEndpoint.cs`)
- Re-check expiry and soft-delete status.
- Stream ZIP file.
- Record `DOWNLOAD_EVENT` with IP, UA, metadata, timestamp.
- Enqueue/send notification based on mode.

### Email Integration (Resend-compatible)

- Wrapper interface: `src/Agora.Application/Notifications/IEmailSender.cs`
- Resend implementation: `src/Agora.Infrastructure/Notifications/ResendEmailSender.cs`
- Config:
  - `Email:Provider = Resend`
  - `Email:Resend:ApiToken`
  - `Email:Resend:ApiUrl` (default `https://api.resend.com`, override for compatible services)

Notification payload includes:
- Share id/url
- Download timestamp UTC
- Recipient IP
- Browser metadata (parsed from UA)

### Logging and Observability

Serilog configuration (`src/Agora.Web/appsettings.Production.json`):
- File sink with `rollingInterval: Day`
- `retainedFileCountLimit: 30`
- Structured fields: request id, share id, uploader email hash, outcome
- Log path: `logs/agora-.log`

### Security and Compliance Controls

- Enforce request size and multipart limits in Kestrel + form options.
- Extension + content-type allowlist; reject dangerous formats if required by policy.
- Use random unguessable tokens (>=128-bit entropy).
- Add rate limiting to upload and download endpoints.
- Use antiforgery for browser form posts.
- Validate/sanitize all user-provided text rendered in download page.
- Restrict background image handling to URL allowlist or controlled upload pipeline.
- Store timestamps in UTC only.

### API Contract (v1)

Authentication modes:
- Authenticated mode (default for production): uploader identity comes from auth session; `uploaderEmail` is optional display/reply field.
- Anonymous mode (optional for MVP): uploader identity is email-only and account-scoped template features are disabled.
- This plan assumes authenticated mode for account template management endpoints.

1. Create share
- `POST /api/shares`
- `multipart/form-data`
- Fields:
  - `uploaderEmail` (string, optional in authenticated mode, required in anonymous mode)
  - `message` (string, optional, max 5000)
  - `zipFileName` (string, optional, max 120)
  - `expiryMode` (`date|indefinite`, required)
  - `expiresAtUtc` (ISO-8601 UTC, required if `expiryMode=date`)
  - `uploaderTimeZone` (IANA time zone, required if `expiryMode=date` and datepicker is date-only)
  - `notifyMode` (`none|once|every_time`, required)
  - `templateMode` (`account_default|per_upload`, required)
  - `template.title` (optional, max 120)
  - `template.h1` (optional, max 120)
  - `template.description` (optional, max 4000)
  - `template.backgroundImageUrl` (optional, https only)
  - `files[]` (1..N, required)
- Response `201`:
  - `shareId`, `shareUrl`, `zipDisplayName`, `expiresAtUtc`, `createdAtUtc`

2. View download page metadata
- `GET /api/shares/{token}`
- Response `200`:
  - `zipDisplayName`, `zipSizeBytes`, `fileCount`, `uploaderMessage`
  - `page.title`, `page.h1`, `page.description`, `page.backgroundImageUrl`
  - `expiresAtUtc`, `isExpired`
- Response `404` for unknown token
- Response `410` for expired/deleted share

3. Download share
- `POST /api/shares/{token}/download`
- Response `200` file stream (`application/zip`)
- Response `410` for expired/deleted share
- Side effects:
  - write `DOWNLOAD_EVENT`
  - evaluate notification mode and enqueue/send email

4. Update account default template
- `PUT /api/account/template`
- Body JSON fields: `title`, `h1`, `description`, `backgroundImageUrl`
- Response `204`

Token storage and lookup:
- Returned URL includes raw bearer token once at creation time.
- Persistence stores only `share_token_hash = SHA-256(token)` plus optional `share_token_prefix` for diagnostics.
- Read flow computes hash from presented token and matches by hash; raw token is never stored.

### Validation and Sanitization Rules

- Filenames:
  - Strip path separators, control chars, and trailing dots/spaces.
  - Normalize Unicode to Form C, then keep ASCII fallback for ZIP entry names when needed.
  - Force `.zip` extension for archive display name.
- Upload files:
  - Reject zero-byte files (unless explicitly allowed later).
  - Reject duplicate filenames after normalization by adding deterministic suffix.
  - Block known dangerous extensions by policy set (for example `.exe`, `.js`, `.bat`) if compliance requires.
- Template text:
  - HTML-encode on render; no raw HTML in v1.
  - Enforce max lengths and trim whitespace.
- Background image URL:
  - `https` only, max 2048 length.
  - Optional domain allowlist setting.

### Download Notification Schema

Email template data contract:
- `shareId` (uuid)
- `shareUrl` (string)
- `zipDisplayName` (string)
- `downloadedAtUtc` (ISO-8601)
- `downloaderIp` (string)
- `downloaderUserAgent` (string)
- `browserMetadata`:
  - `browserFamily`
  - `browserVersion`
  - `osFamily`
  - `osVersion`
  - `deviceType`

Idempotency rules:
- Mode `once`: send only when `first_downloaded_at_utc` transitions `null -> timestamp`.
- Mode `every_time`: send on each successful download event.
- If email fails:
  - persist `notification_sent=false` + error
  - retry with bounded backoff queue (max attempts configurable)

Concurrency-safe `once` implementation:
- Use a single atomic statement in a DB transaction:
  - `UPDATE shares SET first_downloaded_at_utc=@now WHERE id=@id AND first_downloaded_at_utc IS NULL`
- Send `once` notification only when affected row count is `1`.
- If affected row count is `0`, treat as already-first-downloaded and skip `once` notification.

Expiry semantics:
- Internally enforce `expires_at_utc` only.
- If UI uses date-only picker, convert to `23:59:59.999` in uploader local time and then to UTC.
- Display expiry back to users in their local timezone with explicit timezone label.
- Boundary rule: downloads at `now_utc >= expires_at_utc` are rejected with `410`.

### Configuration Contract

`src/Agora.Web/appsettings.json` keys:

```json
{
  "Agora": {
    "StorageRoot": "storage",
    "MaxFilesPerShare": 20,
    "MaxFileSizeBytes": 262144000,
    "MaxTotalUploadBytes": 1073741824,
    "DefaultShareLifetimeDays": 7,
    "DownloadEventRetentionDays": 90
  },
  "Email": {
    "Provider": "Resend",
    "Resend": {
      "ApiToken": "",
      "ApiUrl": "https://api.resend.com",
      "FromAddress": "no-reply@example.com"
    }
  },
  "Serilog": {
    "Using": [ "Serilog.Sinks.File" ],
    "WriteTo": [
      {
        "Name": "File",
        "Args": {
          "path": "logs/agora-.log",
          "rollingInterval": "Day",
          "retainedFileCountLimit": 30
        }
      }
    ]
  }
}
```

Environment variable overrides:
- `Email__Resend__ApiToken`
- `Email__Resend__ApiUrl`
- `Agora__StorageRoot`

### Failure Modes and Recovery Behavior

- ZIP build failure:
  - return `500` with correlation id
  - delete temporary files
  - do not persist share row
- DB save failure after ZIP created:
  - delete just-created ZIP
  - emit error log with share draft id
- Download file missing on disk:
  - return `410` and mark share as unavailable
  - emit high-severity alert
- Cleanup job partial failure:
  - continue next item
  - metric `cleanup_failures_total` increments

### Operational Readiness Checks

Pre-production checklist:
- Verify disk free-space alert thresholds (70/85/95%).
- Verify log rotation and retention after synthetic 31-day retention simulation.
- Verify cleanup job removes expired shares and orphan files.
- Verify retry queue for notification failures.
- Verify UTC consistency in UI and email templates.

On-call runbook queries:
- "Find failed uploads in last 1 hour"
- "Find downloads with notification failure in last 24 hours"
- "Find expired shares still present on disk"

### Rollout Strategy

1. Internal alpha
- enable uploader authentication only for staff accounts
- cap max upload at 100 MB
- validate download notification content and privacy wording

2. Controlled beta
- enable to selected users
- increase limits progressively
- monitor storage growth and event rates

3. General availability
- publish SLA/SLO targets
- finalize alert thresholds
- enable background cleanup with production intervals

### Post-Launch Enhancements (v1.1+)

- Optional password-protected shares
- Object storage backend (`S3/Azure Blob`) with lifecycle policies
- One-time download links
- Webhook support for download events
- Anti-malware scanning pipeline

## Implementation Phases

### Phase 1: Foundation

- [x] Create solution skeleton and projects (`src/Agora.*`, `tests/Agora.*`)
- [x] Add Serilog + file sink wiring with 30-day retention (`src/Agora.Web/Program.cs`)
- [x] Add DB context, migrations, and core entities (`src/Agora.Infrastructure/Persistence/*`)
- [x] Add configuration binding/validation (`src/Agora.Web/Configuration/*`)

Success criteria:
- App boots with health endpoint, DB migration runs, logs written to rolling file.

### Phase 2: Core Sharing Flow

- [x] Implement upload form + endpoint + validation (`src/Agora.Web/Features/Shares/Create*`)
- [x] Implement ZIP creation service (`src/Agora.Application/Archiving/ZipArchiveService.cs`)
- [x] Implement download page rendering (`src/Agora.Web/Features/Shares/View*`)
- [x] Implement download endpoint and event persistence (`src/Agora.Web/Features/Shares/Download*`)

Success criteria:
- User can upload files, receive URL, recipient can view download page and download ZIP.

### Phase 3: Notifications + Expiration

- [x] Implement Resend email sender abstraction with configurable `ApiUrl` (`src/Agora.Infrastructure/Notifications/*`)
- [x] Implement notification modes (`none|once|every_time`) (`src/Agora.Application/Downloads/DownloadNotifier.cs`)
- [x] Implement expiry checks and scheduled cleanup hosted service (`src/Agora.Infrastructure/Jobs/ExpiredShareCleanupService.cs`)

Success criteria:
- Expired shares are blocked and cleaned; notification emails fire according to mode.

### Phase 4: Customization and Hardening

- [x] Implement account default template management (`src/Agora.Web/Features/Templates/*`)
- [x] Implement per-upload template override fields (`src/Agora.Web/Features/Shares/CreateShareViewModel.cs`)
- [ ] Add rate limiting, antiforgery, input sanitization, and abuse controls (`src/Agora.Web/Program.cs`, middleware)
- [ ] Add observability dashboards/queries (logs + optional metrics)

Success criteria:
- Branded page rendering works; core abuse/security controls enabled.

### Phase 5: QA and Release Readiness

- [x] Unit tests for filename resolution, expiry logic, notification mode rules (`tests/Agora.Application.Tests/*`)
- [ ] Integration tests for upload/download lifecycle (`tests/Agora.IntegrationTests/*`)
- [ ] End-to-end browser tests for download page and download UX (`tests/Agora.E2E/*`)
- [ ] Run load tests for concurrent downloads and large uploads (`tests/Agora.Performance/*`)

Success criteria:
- Quality gates pass and operational runbook is documented.

## Alternative Approaches Considered

1. Store original files and ZIP on-demand at download time
- Rejected for v1 due to latency/cost unpredictability and complexity.

2. Store ZIP in object storage (S3/Azure Blob) only
- Good future direction; disk storage selected for initial simplicity.

3. Use signed short-lived download URLs only, no download page
- Rejected because requirement mandates customizable intermediary page.

## Acceptance Criteria

### Functional Requirements

- [x] Uploader can upload one or more files in one submission.
- [x] System creates a ZIP archive and stores it on disk.
- [ ] ZIP filename rule works exactly as specified:
  - [x] Provided custom filename is used.
  - [x] Single upload defaults to uploaded filename without extension, emitted as `<basename>.zip`.
- [x] Uploader can set expiry to a specific date/time or indefinite.
- [x] Share URL opens a download page before download.
- [x] Download page shows file info, uploader message, and download button.
- [x] Uploader can customize title, H1, description, and background image per account or per upload.
- [x] Download event is recorded with IP, browser metadata, and timestamp.
- [x] Notification email mode `once` and `every_time` behave correctly.

### Non-Functional Requirements

- [x] Uploads and downloads are streamed without loading full files into memory.
- [ ] Rate limiting enabled on sensitive endpoints.
- [x] Logs roll daily and retain 30 days on disk.
- [x] All date/time values are UTC in persistence and messaging.

### Quality Gates

- [ ] Unit + integration + e2e tests pass in CI.
- [ ] Security checklist completed (validation, limits, sanitization).
- [ ] Operational docs include backup/cleanup and incident troubleshooting.

## Success Metrics

- Upload success rate >= 99.5%
- Download success rate >= 99.9%
- Notification delivery success >= 99% (excluding provider outages)
- P95 download start latency < 1.5s for files < 250 MB
- Zero orphaned ZIP files older than cleanup retention window

## Dependencies and Prerequisites

- .NET 10 SDK/runtime
- ASP.NET Core 10
- Serilog + Serilog.Sinks.File
- Resend .NET SDK (or compatible service endpoint)
- Relational database provider (SQLite/PostgreSQL)

## Risk Analysis and Mitigation

- Disk exhaustion from large uploads
  - Mitigation: quotas, max limits, cleanup scheduler, disk monitoring alerts.
- Link leakage (bearer URL forwarding)
  - Mitigation: long random token, optional future password or one-time links.
- PII/privacy concerns for download metadata
  - Mitigation: explicit retention policy + masking where required.
- Email provider downtime
  - Mitigation: retry queue + failure audit logs.
- Abuse/bot download storms
  - Mitigation: endpoint rate limits and anomaly alerting.

## Documentation Plan

- `docs/architecture/file-share-service.md`: architecture + data model
- `docs/operations/file-share-runbook.md`: logs, cleanup, rotation, failure handling
- `docs/api/file-share-endpoints.md`: upload/view/download contracts
- `docs/security/file-share-threat-model.md`: threat model and controls

## References and Research

### Internal References

- No existing project files were found in this repository at planning time.
- Global conventions reviewed: `~/.claude/CLAUDE.md` (planning, commit, and environment rules).

### External References

- ASP.NET Core file uploads: https://learn.microsoft.com/en-us/aspnet/core/mvc/models/file-uploads?view=aspnetcore-10.0
- ASP.NET Core hosted services/background jobs: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/host/hosted-services?view=aspnetcore-10.0
- ASP.NET Core rate limiting: https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit?view=aspnetcore-10.0
- ASP.NET Core antiforgery: https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-10.0
- .NET ZipArchive API: https://learn.microsoft.com/en-us/dotnet/api/system.io.compression.ziparchive?view=net-10.0
- Serilog file sink retention/rolling: https://github.com/serilog/serilog-sinks-file
- Resend .NET SDK: https://github.com/resend/resend-dotnet
- Resend API docs: https://resend.com/docs/api-reference/emails

### Deprecation Check (2026-02-17)

- Resend API/SDK: no official deprecation or sunset notice identified in provider docs/repository during this research pass.
- ASP.NET Core 10 docs and APIs above are current targets for this plan date.

## Open Questions

1. Confirm exact upload limits (file count, per-file size, total size).
2. Confirm whether background image is URL-only or uploaded asset managed by this app.
3. Confirm legal/privacy retention rules for IP and user-agent storage.
4. Confirm if recipient access should add optional password protection in v1 or v1.1.
5. Confirm whether anonymous uploader mode is enabled in MVP, or authenticated mode only.
