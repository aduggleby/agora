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
- `Pages/U/Index.cshtml`: public upload intake page (`/u/{token}`).
- `Endpoints/PublicShareEndpoints.cs`: public recipient API surface (`/s/{token}/...`).
- `Services/*`: UI/runtime services (preview generation orchestration, rendering strategies, progress broadcast, OG image generation).
- `Hubs/ShareProgressHub.cs`: SignalR hub for real-time queued share status.
- `Startup/DatabaseHealthCheck.cs`: readiness check behind `GET /ready`.

### `src/Agora.Application`

Application contracts, value models, and cross-layer utilities.

- `Abstractions/*`: interfaces such as `IShareContentStore` and `IEmailSender`.
- `Models/*`: command/result and option models (`CreateShareCommand`, `CreateShareResult`, `AgoraOptions`, email DTOs).
- `Utilities/*`: pure logic helpers (token generation, archive naming, hashing, ZIP encryption, browser metadata parsing).

### `src/Agora.Infrastructure`

Persistence and external-integration implementations.

- `Persistence/AgoraDbContext.cs`: EF Core model and mappings (SQL Server context).
- `Persistence/PostgresAgoraDbContext.cs`: PostgreSQL context (same model, own migration set).
- `Persistence/DatabaseSetup.cs`: `Database:Provider` parsing, EF and Hangfire storage registration.
- `Persistence/DesignTimeDbContextFactories.cs`: `dotnet ef` factories for both contexts.
- `Migrations/*`: SQL Server migration history.
- `Migrations/Postgres/*`: PostgreSQL migration history.
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

- DB: SQL Server (default) or PostgreSQL, selected by `Database:Provider` (`Persistence/DatabaseSetup.cs`). Each provider has its own context type and migration set (`AgoraDbContext` -> `Migrations/`, `PostgresAgoraDbContext` -> `Migrations/Postgres/`). Hangfire storage uses the same database.
- File data: rooted under `AgoraOptions.StorageRoot`.
- Container contract: mutable runtime data under `/app/data`.

## 4. Data Model

### `Share`

Represents a share link and recipient experience settings.

Key fields:

- `ShareToken`: public lookup key, unique.
- `ZipDiskPath`, `ZipDisplayName`, `ZipSizeBytes`: archived payload metadata.
- `DownloadPasswordHash`: hash of recipient password if password-protected.
- `SenderName`, `SenderEmail`, `SenderMessage`: attribution metadata from public upload intake.
- `ShareExperienceType`, `AccessMode`: rendering and access semantics. `AccessMode` is `download_only`, `preview_only`, `preview_and_download` or `direct_link` (a single file served as raw bytes at `/s/{token}`; `ZipDiskPath` stays empty).
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

Authentication, confirmation, lockout, account defaults, display name (`DisplayName`), and public upload token (`UploadToken`, customizable 2-64 character alphanumeric code).

### `AccountTemplate`

Per-account default download page template used when creating new shares.

### `SystemSetting`

Mutable system-level configuration flags stored in DB (for example registration toggle).

## 5. Primary Request and Job Flows

## 5.0 Public Upload Intake Flow

Anonymous users can send files to a registered user through a personal upload link (`/u/{token}`).

1. Each account has an `UploadToken` (generated at registration, customizable to a 2-64 character alphanumeric code from Settings).
2. Visitor opens `/u/{token}`, which resolves the token to a `UserAccount`.
3. Page renders an upload form with sender name, email, optional message, and file picker.
4. Files are staged individually via `POST /api/public-uploads/stage?uploadToken=&draftShareId=` (same staging pipeline as authenticated uploads). Identity comes from the query string and the CSRF token from the `X-CSRF-TOKEN` header, so the upload-link lookup, the open-draft caps per upload code and per client address (`Agora__PublicUploads__MaxOpenDrafts*`) and the scratch preflight (`Agora__Scratch__*`, using the request length) all run before the multipart body is buffered, and a scratch reservation for the buffer (request length, capped at `MaxFileSizeBytes`) is held until the request completes; the request body is capped at `MaxFileSizeBytes` plus 1 MB. After the body is read the draft is re-validated under its lock (exists, owned, unsealed) for every purpose, so a draft finalized or swept meanwhile cannot be recreated by a late request (409). The page only hands out a draft id; the draft is created on the first staged file. `MaxFilesPerShare` and `MaxTotalUploadBytes` are enforced per draft under the draft lock, which the whole stage, every draft refresh, the seal and the zombie sweep share. A draft idle longer than `DraftRetentionHours` stops counting as open and is re-admitted on its next request.
5. On submit, `POST /api/public-uploads/create-share` validates inputs, resolves staged files, preflights scratch for the archive build, checks the owner's daily received-share quota (`MaxSharesPerCodePerDay`, `MaxBytesPerCodePerDay`, counted from `Shares` rows with a `SenderEmail`) as a fast path, seals the draft and queues share creation (further staging and a second submission get 409; if enqueueing fails the seal is removed and the sender gets a retryable 503) using the owner's default notify mode and a per-upload template. The expiry is the owner's default expiry mode; "indefinite" only when the owner chose it, and `Agora__PublicUploads__DefaultExpiryDays` when the mode cannot be resolved. The worker re-checks the daily quota under a per-owner lock held until the share is committed (`ShareManager.CreateReceivedShareAsync`), reserves the archive's scratch (and, with the FileSystem store, durable) bytes for the build, and afterwards removes the whole draft from scratch, submitted or not.
6. The created `Share` stores `SenderName`, `SenderEmail`, and `SenderMessage` for attribution.
7. After submission, the user is redirected back to `/u/{token}?submitted=1`, which renders a dedicated success screen (skipping draft creation and the upload form).
8. Both endpoints are rate-limited under the `PublicUploadEndpoints` policy.

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
6. Job optionally queues preview generation and sends “share ready” email. For public-upload shares, the email uses a “files were sent to you” template with a from-name override (“{configured display name} on behalf of {sender}”) and includes the sender's message. The display name comes from the email provider's `FromDisplayName` setting.

## 5.1.1 Temporary Direct Link Flow

1. The new-share page enables "Create temporary direct link" only when exactly one file is staged and the stage response flagged it `directLinkEligible` (`ContentTypePolicy.Resolve(name).Inline`).
2. `POST /api/shares/direct-link` (`DirectLinkEndpoints`, authenticated, CSRF token in the header, 16 KB JSON body) re-validates the draft, the single file and the duration (`DirectLinkDuration`: `30m`, `6h`, `1d`, `7d`), preflights the durable demand against the scratch budget, then seals the draft and runs `ShareManager.CreateDirectLinkShareAsync` inline (no queue).
3. `CreateDirectLinkShareAsync` persists the file through `IShareContentStore` (same `shares/yyyy/MM/{guid}/` layout), takes the owner lock (owner exists and is enabled) and inserts the `Share` with `AccessMode = direct_link`, `NotifyMode = none`, `ExpiresAtUtc = now + duration`, `ZipDisplayName` = file name and no archive. A failed insert removes the stored file again.
4. The endpoint finalizes the draft and returns `{url, token, expiresAtUtc}`. The browser copies the URL to the clipboard inside the click, notes the copy in `sessionStorage` (`agora.directLink.copied` = token) and navigates to `/shares/created/{token}`; that page renders the direct-link card (URL, expiry, copy button) and, when the flag matches its token, shows the "Copied" confirmation once and clears the flag. A failed request keeps the user on the form with the error line; the form stays locked from the click until the navigation.
5. `GET /s/{token}` for a live direct link records a download event for every request (no email) and streams the bytes through `ObjectResults.UserContent` (extension-derived type, `nosniff`, sandbox CSP). An expired, deleted or purged direct link renders the expired page with 410 (ordinary deleted shares stay 404); `/files`, `/download`, `/og-image` and `/api/shares/{token}` answer 403/302/404/404 as the mode allows neither preview nor archive download.
6. `CleanupExpiredSharesAsync` purges direct links as soon as they are expired (other shares keep the 7-day grace for "Re-enable 24h", which refuses direct links).

## 5.2 Public Recipient Access Flow

Public endpoints are in `PublicShareEndpoints`:

- `/s/{token}` (Razor page) resolves share by `ShareToken`; for a direct link it serves the file bytes (see 5.1.1).
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
- display name management
- upload token customization (user-chosen or auto-generated codes)
- role and enable/disable admin operations

Auth email delivery is queued through `AuthEmailJob` and `IEmailSender` implementation.

## 6. Storage and Filesystem Layout

Relative to `StorageRoot` (`Agora__StorageRoot`):

- `uploads/staged/*`: temporary uploaded files before share creation
- `uploads/staged-template-backgrounds/*`: temporary background uploads (purpose-isolated)
- `uploads/drafts/{draft-id}/draft.json`: draft template state (`PublicUpload` selects the shorter anonymous retention); `uploads/drafts/{draft-id}/staged/{upload-id}` are the per-draft slot markers (declared size) the stage-time quota counts; `uploads/drafts/{draft-id}/sealed` marks a submitted draft
- `uploads/draft-index/{token|ip}/{sha256}/{draft-id}`: open-draft markers per upload code and client address (anonymous uploads only)
- `uploads/templates/*`: account template background assets
- `uploads/share-create-status/*`: hashed token keyed JSON progress status files (swept after `ZombieUploadRetentionHours`)
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
- The middleware lives in `Startup/CsrfValidation.cs`. Endpoints carry `UploadEndpointMetadata`; the three stage endpoints (`Endpoints/UploadStagingEndpoints.cs`) require the token in the `X-CSRF-TOKEN` header (the bundled CSRF client sets it on every XHR/fetch) and are refused before anything reads the form, so validation never buffers a multipart body. The decision keys on the resolved endpoint's metadata, not on the path, so trailing slashes or case variants cannot bypass it. The submit endpoints carry the marker with a 1 MB body limit.

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
- scratch budget (`Scratch:MaxBytes`, `Scratch:MinFreeBytes`) and anonymous upload budgets (`PublicUploads:*`)
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
- dashboard splits shares into "Own" and "Received" sections; received shares (identified by non-empty `SenderEmail`) display sender name, email, and message
- quick-share drag-and-drop on dashboard (`quick-share-dropzone.ts`): stages files, enforces client-side limits (max files, per-file size, total size), supports cancel mid-upload
- upload limits display: dropzone shows configured limits inline from server-rendered `data-*` attributes (`upload-limits.ts`)
- image lightbox (`lightbox.ts`): full-screen overlay for gallery images with keyboard navigation (Escape to close, arrow keys to navigate), per-image download link

## 12. Extensibility Points

Primary seams for additive change:

- `IShareContentStore` for storage backend changes
- `IEmailSender` for delivery provider changes
- `IShareExperienceRenderer` strategy set for recipient UX modes
- `IDownloaderGeoLookup` for IP geolocation provider swaps
- EF Core migrations for schema evolution (applied automatically at startup; failure stops the app)

## 13. Constraints and Invariants

- Namespaces and projects remain under `Agora.*`.
- Token-at-rest hashing behavior for account/security tokens remains intact.
- Download password remains hashed at rest.
- Mutable runtime data stays under storage root (`/app/data` in container).
- Log retention remains daily rolling with 30-day retention.

## 14. Deployment Model (Summary)

Supported topologies:

- single container with external SQL Server and bind/volume-mounted `/app/data`
- reverse-proxy fronted deployment with forwarded headers enabled

The architecture is intentionally monolithic for operational simplicity while preserving clear boundaries for future extraction if needed.
