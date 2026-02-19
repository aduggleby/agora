# Agora Architecture

## 1. System Overview

Agora is a monolithic ASP.NET Core 10 application for authenticated file sharing with public recipient pages.

Core capabilities:

- Authenticated uploaders create shares from one or more files.
- Shares are exposed through public tokenized URLs (`/s/{token}`).
- Files are archived to ZIP (optionally encrypted when download password is configured).
- Recipient pages can render archive-only mode or preview-capable modes.
- Long-running work (share creation, previews, emails, cleanup) is handled by Hangfire jobs.

The system is designed as a layered monolith with clear project boundaries and a single process runtime.

## 2. Project Structure and Responsibilities

### `src/Agora.Web`

Presentation and runtime composition layer.

- `Program.cs`: DI setup, middleware pipeline, endpoint mapping, Hangfire servers, recurring jobs.
- `Pages/*`: Razor Pages for authenticated UX (new share, account settings, admin, etc.).
- `Endpoints/PublicShareEndpoints.cs`: public recipient API surface (`/s/{token}/...`).
- `Services/*`: UI/runtime services (preview generation orchestration, rendering strategies, progress broadcast, OG image generation).
- `Hubs/ShareProgressHub.cs`: SignalR hub for real-time queued share status.
- `Startup/SchemaUpgradeRunner.cs`: post-migration compatibility upgrades.

### `src/Agora.Application`

Application contracts, value models, and cross-layer utilities.

- `Abstractions/*`: interfaces such as `IShareContentStore` and `IEmailSender`.
- `Models/*`: command/result and option models (`CreateShareCommand`, `CreateShareResult`, `AgoraOptions`, email DTOs).
- `Utilities/*`: pure logic helpers (token generation, archive naming, hashing, ZIP encryption, browser metadata parsing).

### `src/Agora.Infrastructure`

Persistence and external-integration implementations.

- `Persistence/AgoraDbContext.cs`: EF Core model and mappings.
- `Persistence/Migrations/*`: schema history and migration steps.
- `Services/ShareManager.cs`: core share domain workflow orchestrator.
- `Services/ShareContentStore.cs`: file storage persistence/path safety.
- `Services/*Email*`: notification and auth email delivery adapters.
- `Auth/AuthService.cs`: account lifecycle/authentication workflows.

### `src/Agora.Domain`

Persistence entities representing durable state.

- `Share`, `ShareFile`, `DownloadEvent`, `UserAccount`, `AccountTemplate`, `SystemSetting`.

### Tests

- `tests/Agora.Application.Tests`: unit tests for application/infrastructure logic.
- `tests/e2e`: Playwright end-to-end UI/API flows.

## 3. Runtime Topology

Single web process hosts:

- ASP.NET Core request pipeline
- Razor Pages and minimal APIs
- SignalR hub
- Hangfire dashboard and workers

Hangfire worker queues:

- `default`: normal background jobs (share creation completion steps, email jobs, cleanup jobs)
- `previews`: preview generation jobs (`SharePreviewJobService.GeneratePreviewAsync`)

Storage model:

- DB: SQLite by default, SQL Server supported by connection string detection.
- File data: rooted under `AgoraOptions.StorageRoot`.
- Container contract: mutable runtime data under `/app/data`.

## 4. Data Model

### `Share`

Represents a share link and recipient experience settings.

Key fields:

- `ShareToken`: public lookup key, unique.
- `ZipDiskPath`, `ZipDisplayName`, `ZipSizeBytes`: archived payload metadata.
- `DownloadPasswordHash`: hash of recipient password if password-protected.
- `ShareExperienceType`, `AccessMode`: rendering and access semantics.
- `PageTitle`, `PageH1`, `PageDescription`, `BackgroundImageUrl`, `PageBackgroundColorHex`, `PageContainerPosition`: download-page customization.
- `ExpiresAtUtc`, `DeletedAtUtc`: lifecycle gates.

### `ShareFile`

Per-file metadata for uploaded content and preview behavior.

- Original filename/size
- Stored relative path
- Render type and detected content type

### `DownloadEvent`

Immutable-ish audit/event stream for downloads.

- IP, user agent, parsed browser metadata
- Notification delivery status fields

### `UserAccount`

Authentication, confirmation, lockout, and account defaults.

### `AccountTemplate`

Per-account default download page template used when creating new shares.

### `SystemSetting`

Mutable system-level configuration flags stored in DB (for example registration toggle).

## 5. Primary Request and Job Flows

## 5.1 Share Creation Flow

1. Uploader selects files and options in `/shares/new`.
2. Files are staged under storage roots (separated by upload purpose).
3. `QueuedShareCreationJob` validates staged uploads and limits.
4. `ShareManager.CreateShareAsync`:
   - persists share files into content store
   - builds ZIP archive
   - optionally encrypts ZIP when recipient password is set
   - resolves template source (per-upload vs account default)
   - copies template background to share-specific location when needed
   - creates `Share` row + `ShareFile` rows, enforcing unique token
5. Job updates status (`ShareCreationStatusStore`) and broadcasts over SignalR (`ShareProgressBroadcaster`).
6. Job optionally queues preview generation and sends “share ready” email.

## 5.2 Public Recipient Access Flow

Public endpoints are in `PublicShareEndpoints`:

- `/s/{token}` (Razor page) resolves share by `ShareToken`.
- `/s/{token}/download` performs gated download behavior.
- `/s/{token}/files`, `/preview`, `/thumbnail`, `/preview-status` serve preview surfaces when allowed.
- `/s/{token}/background` serves custom background image from internal marker.
- `/s/{token}/og-image` dynamically generates social preview image.

Gate checks consistently enforce:

- token exists
- share is not expired/deleted
- preview mode is enabled when preview resources are requested
- password-protected shares block preview APIs

## 5.3 Preview Generation Flow

1. `QueuedShareCreationJob` enqueues share preview jobs when previews are enabled.
2. `SharePreviewJobService.QueueForShareAsync` fans out per-file jobs.
3. `GeneratePreviewAsync` (queue `previews`) creates preview assets:
   - lock file prevents duplicate concurrent generation
   - failure marker records generation failure
   - thumbnail generated for image files
4. Public preview endpoints:
   - return ready preview when available
   - return pending placeholder while generation is in progress
   - return unavailable placeholder when unsupported/failed
   - expose `X-Agora-Preview-State` header for client behavior

## 5.4 Download Notification Flow

1. Download endpoint records event via `ShareManager.RecordDownloadAsync`.
2. Notification mode (`none`, `once`, `every_time`) determines whether to queue email.
3. `EmailNotificationJob` builds and sends download notification.
4. Optional geolocation lookup through `IDownloaderGeoLookup` (`IpWhoIsDownloaderGeoLookup`).

## 5.5 Authentication and Account Flow

`AuthService` handles:

- registration
- email confirmation and resend
- login with lockout protection after repeated failures
- forgot/reset password
- email/password change confirmation workflows
- role and enable/disable admin operations

Auth email delivery is queued through `AuthEmailJob` and `IEmailSender` implementation.

## 6. Storage and Filesystem Layout

Relative to `StorageRoot` (`Agora__StorageRoot`):

- `uploads/staged/*`: temporary uploaded files before share creation
- `uploads/staged-template-backgrounds/*`: temporary background uploads (purpose-isolated)
- `uploads/templates/*`: account template background assets
- `uploads/share-create-status/*`: hashed token keyed JSON progress status files
- `shares/YYYY/MM/{share-guid}/...`: persisted per-share source files
- `zips/YYYY/MM/*.zip|*.agz`: downloadable archives
- preview assets under paths derived by `SharePreviewPaths`

Important invariant: template background uploads are purpose-separated so they do not appear as share files or previews.

## 7. Security Architecture

## 7.1 Identity and Access

- Cookie authentication with role-based authorization (`AdminOnly`).
- Public shares are bearer-by-URL-token (`ShareToken`).
- Share ownership checks on authenticated APIs compare uploader email/claims.

## 7.2 CSRF Protection

- Antiforgery token emitted on safe methods.
- Validation required on unsafe methods except explicitly allowed E2E test routes and Hangfire dashboard path.

## 7.3 Password and Token Handling

- Account passwords: hashed (never plaintext).
- Download passwords: hashed in `Share.DownloadPasswordHash`.
- Share URL token: stored plaintext for direct lookup and URL use.
- Confirmation/reset tokens are generated and stored as hashes where applicable in account flows.

## 7.4 Path and File Safety

- Path traversal defenses in `ShareContentStore.ResolveAbsolutePath` and public file-serving endpoints.
- Internal marker format (`internal:`) for background image references.
- File existence and expiry checks before serving content.

## 7.5 Rate Limiting

Configured in `Program.cs`:

- Auth endpoints: sliding window per source IP.
- Download endpoints: fixed window per `(token, ip)`.
- Global authenticated traffic limiter per authenticated user identity.

## 8. Configuration Architecture

Bound option classes:

- `AgoraOptions` (`Agora` section)
- `EmailSenderOptions` (`Email:Resend`)
- `FileSystemEmailOptions` (`Email:FileSystem`)

High-impact settings:

- size limits (`MaxFileSizeBytes`, `MaxTotalUploadBytes`, `MaxFilesPerShare`)
- retention windows (`DownloadEventRetentionDays`, `ZombieUploadRetentionHours`)
- storage root and public base URL
- email provider mode and provider credentials

## 9. Background Processing and Scheduling

Recurring jobs configured at startup:

- `cleanup-expired-shares` every 30 minutes
- `cleanup-zombie-uploads` every 15 minutes

On-demand jobs include:

- queued share creation
- preview generation per file
- auth email dispatch
- download notification dispatch
- delayed share file deletion after logical delete

## 10. Observability and Operations

- Structured logging via Serilog.
- Hangfire dashboard at `/hangfire` (admin-only).
- Download events persisted for audit/notification reporting.
- Share creation state persisted to JSON status entries + broadcast via SignalR.

Operational defaults emphasize container predictability:

- one writable volume
- env-var config only
- logs and mutable artifacts under data root

## 11. Frontend Architecture

Server-rendered Razor Pages with TypeScript-enhanced interactions.

- TypeScript source: `src/Agora.Web/scripts/ts`
- Bundled output: `src/Agora.Web/wwwroot/js`
- Tailwind CSS build from `src/Agora.Web/Styles/tailwind.css`
- Public share page uses inline CSS for self-contained rendering portability

Frontend behavior of note:

- share creation status polling + SignalR updates
- preview availability polling/retry logic
- progressive enhancement for file browser/gallery experiences

## 12. Extensibility Points

Primary seams for additive change:

- `IShareContentStore` for storage backend changes
- `IEmailSender` for delivery provider changes
- `IShareExperienceRenderer` strategy set for recipient UX modes
- `IDownloaderGeoLookup` for IP geolocation provider swaps
- `SchemaUpgradeRunner` for non-breaking runtime schema compatibility upgrades

## 13. Constraints and Invariants

- Namespaces and projects remain under `Agora.*`.
- Token-at-rest hashing behavior for account/security tokens remains intact.
- Download password remains hashed at rest.
- Mutable runtime data stays under storage root (`/app/data` in container).
- Log retention remains daily rolling with 30-day retention.

## 14. Deployment Model (Summary)

Supported topologies:

- single container with SQLite and bind/volume-mounted `/app/data`
- single container with external SQL Server
- reverse-proxy fronted deployment with forwarded headers enabled

The architecture is intentionally monolithic for operational simplicity while preserving clear boundaries for future extraction if needed.
