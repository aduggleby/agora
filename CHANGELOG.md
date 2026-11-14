# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- AI agents can use an account through one MCP endpoint (`/mcp`) and the same JSON API under `/api/v1`: sign in with the standard MCP OAuth flow (discovery documents and dynamic client registration included) or use a token created in Account > Settings > Connected apps. Agents upload files (inline up to 1 MiB per call, larger through one-time upload URLs), create shares with all the new-share options, list and delete shares, and, with "All my shares" access, download files. Each connection is limited to "Only shares it creates" or "All my shares"; the level can be changed and the agent revoked in Connected apps.
- "Let AI agents send files to my upload link" (Account > Settings, off by default): while on, agents can send files to the upload link through `/mcp?upload=<code>` or the HTTP API without signing in, within the link's existing limits. The upload page then links to `/u/<code>/llms.txt` with instructions. Files sent this way are marked with an "Agent" badge, and the notification email says they came through the agent interface and that the sender details are not verified.
- `Agora__Agents__AllowedRedirectHosts__0`, `__1`, ... (one variable per host; a comma separated value is not read) add trusted `https` redirect hosts for MCP client registration. See `docs/api/agents.md`.

### Changed
- `POST /api/v1/auth/token` also accepts form encoded bodies and an optional `resource` parameter, and `/api/v1/me` reports `accessLevel` and `limits`. `DELETE /api/v1/shares/{token}` deletes shares within an agent token's access level; capture app tokens behave as before.
- Registered MCP client ids are protected with the DataProtection keys: back up `keys/` with the data volume.
- Logs redact agent upload codes, one-time URLs and passwords.

## [0.10.4] - 2026-11-13

### Changed
- Drafts now expire after their idle time even if the page stays open: only uploading a file refreshes a draft. Opening or reloading the new-share page, saving a design or a refused request no longer keeps it (and its staged files) alive. A draft idle for more than 24 hours (6 hours for an upload link) is cleaned up, so files uploaded to a page that was left open overnight are gone and must be added again.
- Signed-in accounts may hold up to 50 GB of staged uploads (files and template backgrounds together, across all drafts); admins are exempt. Configurable with `Agora__MaxStagedBytesPerAccount`. Over the limit an upload is refused with 413.
- An upload link may hold up to 20 GB in open drafts (`Agora__PublicUploads__MaxOpenDraftBytesPerToken`), and all open anonymous drafts together up to half of the scratch budget (`Agora__PublicUploads__MaxOpenDraftScratchFraction`, see the README for the formula). Over the first limit an upload is refused with 413, over the second with 507.
- A share creation job that finds the scratch area full is retried later instead of failing and deleting the staged files.
- A request to an upload link's create-share route without files is refused before the draft is looked at.
- `/api/public-uploads/create-share` with an unknown, foreign or already submitted draft id now answers 409 instead of opening a new draft.

### Fixed
- A custom share link is now claimed when the share is submitted and held until the share is created or creation fails; a stranded claim is released after the upload retention (24 hours by default).
- Submitting the same draft twice at once no longer leaves the losing request's share link reserved, and a share link that cannot be confirmed answers 503 (try again) instead of 500.

## [0.10.3] - 2026-11-13

### Changed
- Disabling an account also suspends its share links and direct links: while it is disabled they answer like an expired share (410), and download notifications and ready-link emails to it are skipped. Enabling the account brings the links back unchanged.
- The new-share page always generates the share link itself; it no longer takes a link from the page URL. When a chosen link is invalid or already taken, the page shows the reason (with a free suggestion) in place.
- Background images are checked when uploaded: they must be readable images within 40 million pixels for JPG and WEBP or 16 million for PNG. Link-preview images decode backgrounds in the same limited decode slots and time budget as file previews; when none is free in time, a plain preview is served and not stored.
- Deleting shares in a batch takes at most 100 at a time, and deleting an already deleted share from the web UI no longer queues another cleanup job.
- Routing and EF Core command logs default to Warning.

### Fixed
- Share links in `/api/shares/...` and `/api/v1/shares/...` request paths (and `/S/`, `/U/` in any case) are redacted in logs like `/s/` links; the `gate` query value is redacted too.
- Share creation interrupted by a restart or deploy is retried instead of failing; if the share was already created, the job completes instead of creating it twice.

## [0.10.2] - 2026-11-12

### Added
- Pasting files (Ctrl/Cmd+V) anywhere on an upload page uploads them like a drop: home, new share, public upload link and the landing page designers. Clipboard images such as screenshots get a timestamped name (`pasted-YYYY-MM-DD-HHMMSS.png`). A paste into a text field that also carries text stays a normal text paste. Files copied in a file manager arrive as files where the browser supports it.

### Fixed
- The landing page designers show a hint instead of failing when a dropped or pasted file is not a .jpg, .jpeg, .png or .webp image.

## [0.10.1] - 2026-11-06

### Added
- Files can be dropped anywhere on an upload page (home, new share, public upload link, landing page designers), not only on the dropzone; a full-page hint shows while files are dragged over the window.
- Password-protected share pages have an Unlock step: until the password is entered, the page and its link previews show only "Password-protected share" (no file name, count, size, title, description or background).
- `Agora__Auth__MaxConcurrentPasswordHashes` caps concurrent password hashing (default: number of processors); requests over the cap get a "server busy, try again" answer.

### Changed
- "Every time" download notifications are combined: at most one email per share every 5 minutes, summarizing the downloads since the previous email.
- Confirming a new account's email address asks for the account password.
- Request bodies are limited to 1 MB except on upload endpoints; requests to signed-in endpoints without a session are refused before their body is read, and requests to unknown paths answer 404 without being read. `POST /api/shares` requires the `X-CSRF-TOKEN` header (the share page now submits it with fetch).
- Uploads: at most two at a time per account and draft (per address and draft for public upload links; extra requests get 429), each reserves only what its draft can still take, and uploads slower than 32 KiB/s after the first minute are dropped. The new-share page uploads two files at a time.
- Per-address limits and login lockouts treat an IPv6 /64 as one client.
- Expired or deleted direct links show a generic expired page without the file name.
- Retrying a failed preview is possible again 30 minutes after the failure.
- Share pages, backgrounds and direct-link views count toward the download rate limit; HEAD requests to direct links are not recorded as downloads. Signed-in users other than the owner are now counted as downloads.
- Original files, archives, direct links and backgrounds are sent with `Cache-Control: private, no-store`.
- The public upload sender message is limited to 2000 characters.

### Fixed
- A background image dropped on the account landing page designer is now saved, not only previewed.
- Replacing the account background image deletes the previous image.
- Public-upload drafts and signed-in drafts can no longer be used through each other's endpoints.
- Accounts awaiting email confirmation lock out after repeated wrong passwords like confirmed accounts.

### Security
- Updated Microsoft.Data.SqlClient and System.Security.Cryptography.Pkcs; release images are built on a current .NET runtime.
- `appsettings.Development.json` is no longer included in the published app.

## [Agora Capture 0.1.5] - 2026-11-04

### Changed
- Implements the approved minimal Settings design, with a compact connection card, Keep links for explanation and Launch at login.
- Area and full-screen capture now have independent shortcut recorders, with preset migration, duplicate/conflict validation and safe cancellation.

## [Agora Capture 0.1.4] - 2026-11-04

### Added
- README walkthrough with tray-menu preview, editor, approval and confirmation images, plus reproducible sample-data renderers.

## [Agora Capture 0.1.3] - 2026-11-04

### Fixed
- Successful sharing immediately closes the source editor before showing the link toast. Failed uploads retain the editor and annotations for retry.

## [Agora Capture 0.1.2] - 2026-11-04

### Changed
- Labels the editor expiry dropdown "Keep for" and moves it to the right of Share link.

## [Agora Capture 0.1.1] - 2026-11-04

### Changed
- Browser callback page now matches Agora's authorization screen, including bundled fonts, distinct approval/declined/error states and a return-to-app link.
- Callback pages are self-contained with no-store/no-referrer headers and a restrictive Content Security Policy; query codes are never reflected.

## [Agora Capture 0.1.0] - 2026-11-04

### Added
- Native macOS menu bar app with area/window/full-screen capture, minimal annotation editor, PNG export, sky-blue Focus icon and white menu bar mark.
- API v1 integration with browser PKCE sign-in, Keychain storage, upload progress, server expiry choices, clipboard/toast feedback, recent-link deletion and disconnect.
- Mac app build/install/restart tooling and automatic GitHub prereleases on pushes to `main`, including an app ZIP and SHA-256 checksum.
- 21 Swift tests covering API contracts, real loopback sign-in, annotation editing/resize and export orientation/dimensions.

## [0.10.0] - 2026-11-04

### Added
- Connected apps: a desktop app (the upcoming macOS capture app) signs in through the browser. You approve the device on a new consent page (OAuth authorization code with PKCE and a loopback redirect), and the app receives a revocable API token. The app never sees your password.
- Settings lists connected apps (device, connected, last used) with Revoke. Tokens also stop working after a password change or reset, when the account is disabled, or after 180 days without use.
- API v1 for connected apps (`docs/api/v1.md`): `GET /api/v1/me`, `POST /api/v1/captures` (upload one PNG or JPEG as a temporary direct link in a single call), `DELETE /api/v1/shares/{token}` (delete one of your own direct links), token exchange and revocation.

### Changed
- API tokens are accepted only by `/api/v1` endpoints, and every other page and endpoint accepts only the browser session.
- Signing in returns you to the page that asked for it (local paths only) instead of always going to the home page.

### Security
- API tokens and authorization codes are stored only as SHA-256 hashes and are redacted from logs.

## [0.9.27] - 2026-10-14

### Fixed
- Short 503 outages when object storage was briefly slow: the readiness check now gives up on the storage check after 2 seconds and, if storage worked within the last 2 minutes, reports a degraded but ready state instead of failing, so the reverse proxy no longer takes the app out of rotation.

## [0.9.26] - 2026-10-14

### Fixed
- Stylesheet and script links carry a content hash, so browsers pick up updated CSS and JS after an upgrade instead of serving cached copies (the 0.9.23 direct-link control looked unstyled with a stale stylesheet).

## [0.9.25] - 2026-10-14

### Fixed
- My shares and received-file rows stay on one line: long names truncate with an ellipsis and show the full name on hover, the direct-link badge has proper padding, and dates use a compact form with the full date in the tooltip.
- The received-files note no longer claims those uploads never expire (they follow your default share expiry); the table shows their expiry.
- The footer version renders (0.9.24 printed the Razor expression).

## [0.9.24] - 2026-10-14

### Added
- The app version is shown in the page footer.

## [0.9.23] - 2026-10-14

### Fixed
- The direct-link duration control no longer clips its "Expires in" label in browsers that size nested selects differently; on phones the control and the buttons stack full width.

### Changed
- Creating a temporary direct link opens the created page (with the copied-to-clipboard confirmation) instead of an inline panel.

## [0.9.22] - 2026-10-13

### Added
- Temporary direct links: with exactly one inline-safe file staged, "Create temporary direct link" creates a share instantly whose `/s/{token}` URL returns the file itself (no download page), expiring after 30 minutes, 6 hours, 1 day or 7 days. The link is shown and copied to the clipboard; direct links appear in My shares with a badge, count every view, never send notifications and are purged right after expiry.
- Security headers are set by the app (`nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, HSTS over https; `Agora__SecurityHeaders__Enabled`), plus a report-only Content-Security-Policy with a per-request script nonce.
- Password hashes use a versioned PBKDF2 format with 600,000 iterations and are upgraded transparently at sign-in; new passwords must be 8 to 128 characters.

### Changed
- Shares, templates, drafts and staged uploads belong to the account id (backfilled once from the address at startup); authenticated account operations use the session's account id. Deleting an account removes its template and shares.
- Registration, sign-in, forgot-password and confirmation links answer uniformly; an unconfirmed address can be claimed by whoever registers it again and confirms the mailbox; lockout is per account and client IP; all credential changes rotate the session stamp and clear pending tokens; email changes notify the old address and re-address the user's shares.
- Confirmation links open a page and act only on the confirm button (POST), so mail scanners cannot consume them.
- Deleted shares answer 404 and expired ones 410 on every public route; the link-preview image is cached per share and gated like the rest; preview generation is claimed once per retention window; the anonymous share summary reveals nothing for password-protected shares; custom share tokens need 8 characters, upload codes 8 (generated: 12).
- The created page uses `/shares/created/{token}` (old links redirect); share pages send `Referrer-Policy: same-origin`; tokens no longer appear in logs.
- Public-upload sender names are bounded and sanitised; the notification From display name is quoted safely.
- The container image runs as the `app` user (UID 1654): existing bind mounts must be owned by that user (see README).
- Sealed drafts hold a processing lease so the scratch sweep never removes in-flight uploads.

## [0.9.21] - 2026-10-13

### Changed
- Previews, thumbnails and Open Graph images are rendered with SkiaSharp (already bundled for PDF rendering) instead of SixLabors.ImageSharp, which is removed together with its five open advisories. Only PNG, JPEG, WEBP and BMP sources get generated previews, selected by magic bytes and the codec header; PNGs with duplicate headers, compressed text chunks or more than 64 KB of ancillary data are refused before decoding; raster decodes share two slots under the preview time budget.
- Open Graph panels have rounded corners.

## [0.9.20] - 2026-10-13

Security hardening release. **Breaking:** `Agora__PublicBaseUrl` is now required outside `Development`/`E2E` (startup fails without it), and `X-Forwarded-*` headers are honoured only from loopback and the proxies listed in `Agora__TrustedProxies`. Upgrading signs every existing session out once.

### Added
- `Agora__TrustedProxies`: comma-separated IPs and CIDRs of the reverse proxies whose `X-Forwarded-For/Proto/Host` headers are trusted. Empty means loopback only.
- Session revalidation: users carry a security stamp that rotates on password change or reset, email change, role change and disable; cookies (and SignalR connections) are re-checked against the database every `Agora__Auth__SessionRevalidationMinutes` (default 5). `Agora__Auth__SessionLifetimeDays` (default 14, sliding) and `Agora__Auth__SecureCookies` (`Auto`/`Always`/`SameAsRequest`).
- Preview limits: `Agora__Previews__MaxSourceBytes` (64 MB), `MaxSourcePixels` (50 MP), `TimeoutSeconds` (30). Only PNG, JPEG, WEBP and BMP sources get generated previews; PDFs render at most 1200 px on the long side.
- `Agora__RateLimits__AnonymousPerMinute` (default 1200): per-IP budget for anonymous requests.
- `Agora__GeoLookup__Enabled` (default `true`): set to `false` to stop sending downloader IPs to ipwho.is.
- Upload quotas: per-draft file count and bytes are enforced at stage time (`Agora__MaxFilesPerShare`, `Agora__MaxTotalUploadBytes`), open drafts are capped per upload code and per client IP (`Agora__PublicUploads__MaxOpenDraftsPerToken` 20, `MaxOpenDraftsPerIp` 10), received shares are capped per account and day (`Agora__PublicUploads__MaxSharesPerCodePerDay` 50, `MaxBytesPerCodePerDay` 20 GB), and staging or share creation is refused with 507 when scratch would exceed `Agora__Scratch__MaxBytes` or leave less than `Agora__Scratch__MinFreeBytes` (1 GB) free.

### Changed
- Uploaded files are served by their extension-derived type only; the client-declared type is never stored. Raster images, common video/audio, PDF and plain text display inline, everything else downloads as `application/octet-stream`. Every user-content response (files, backgrounds, previews, archives) carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox` (inline PDFs excepted).
- SVG files are no longer accepted as download-page backgrounds.
- Emailed links (password reset, email confirmation, share notifications) and `og:url` are always built from `Agora__PublicBaseUrl`, never from the request host.
- The forgot-password, reset-password and resend-confirmation page handlers share the `AuthEndpoints` rate limit.
- Received shares from public upload links use the owner's default expiry (7 days unless changed in the account settings; `Agora__PublicUploads__DefaultExpiryDays` is the fallback) instead of never expiring.
- The zombie sweep (`Agora__ZombieUploadRetentionHours`) now also covers abandoned drafts, share-creation status files and the draft index.
- Preview jobs retry once instead of ten times; rejected sources are marked failed.
- Admins can no longer disable or delete their own account from the admin forms.
- PDFtoImage 5.2.0 -> 5.4.0.

### Fixed
- The admin "allow registration" toggle could not re-enable registration (the form posted `false,true`).

### Notes
- `SixLabors.ImageSharp` stays at 3.1.12 in this release (replaced by SkiaSharp in 0.9.21). The five open advisories are unreachable here: TIFF encoding is never used, the TIFF decoder is not registered, histogram equalization is never called, and ICC profiles are never parsed (`SkipMetadata`).

## [0.9.19] - 2026-10-13

### Added
- Object storage backend: `Storage__Provider=S3` with `Storage__S3__ServiceUrl|Region|Bucket|AccessKeyId|SecretAccessKey|ForcePathStyle` (Hetzner Object Storage, MinIO, other S3-compatible stores). The default `FileSystem` provider keeps content under `StorageRoot` exactly as before, so existing installs need no change.
- Share files, archives, download-page backgrounds and previews are stored through the object store; object keys are the existing relative paths (no database change). Downloads are proxied through the app with range support for single files.
- `/ready` also checks the bucket in S3 mode (healthy results cached for 30 s).

### Changed
- Archives (and password-protected `.agz` files) are built in `StorageRoot/tmp` and then uploaded. If share creation fails at any step, every object already uploaded is deleted again.
- Password-protected downloads decrypt into `StorageRoot/tmp` (was `downloads/tmp`); the plaintext is deleted on every failure path and after the response.
- Deleting a share also deletes its previews (`previews/{shareId}/`), which were left behind before. A preview finished after its share was deleted is removed.
- The zombie cleanup also sweeps `StorageRoot/tmp` files and stale preview `.lock` markers older than `Agora__ZombieUploadRetentionHours`.

### Removed
- Unused `ExpiredShareCleanupService` (expired-share cleanup runs as a Hangfire recurring job).

## [0.9.18] - 2026-10-12

### Added
- PostgreSQL support: `Database__Provider=Postgres` (default stays `SqlServer`). EF Core and Hangfire (`Hangfire.PostgreSql`) use the same database; PostgreSQL has its own migration set (`InitialPostgres`).
- `GET /live` and `GET /ready` health endpoints (anonymous, not rate limited; `/ready` checks the database).
- DataProtection keys are persisted to `DataProtection__KeysPath` (default: `keys` next to the storage root, `/app/data/keys` in the container), so sign-ins survive restarts.
- Logging settings `Agora__Logging__File__Enabled|Path|RetainedDays`; logs always go to stdout as well.
- `scripts/add-migration.sh` adds a migration to both migration sets.
- E2E suite runs against SQL Server or PostgreSQL (`PLAYWRIGHT_E2E_DB`).

### Changed
- A missing `ConnectionStrings__Default` is now a startup error. The SQLite runtime fallback, the `Server=` connection-string heuristic and the Hangfire in-memory fallback are removed.
- Emails on shares and account templates are stored lower-cased, like user emails.
- Notify-once first-download tracking uses a provider-neutral conditional update.
- Multipart upload buffering (`ASPNETCORE_TEMP`) defaults to `<StorageRoot>/tmp/aspnet` instead of the system temp directory.
- Legacy `Serilog__WriteTo__0__Args__path` and `retainedFileCountLimit` overrides are still honoured.
- `/live` and `/ready` skip antiforgery and set no cookies.
- Upgrade note: persisting DataProtection keys (application name `Agora`) signs all users out once when upgrading to 0.9.18. Previously keys were not persisted in containers, so every restart already did this; from now on sign-ins survive restarts.
- EF Core packages updated to 10.0.4.

### Removed
- Unused legacy `SchemaUpgradeRunner` and `V0901`/`V0902` migration files.

## [0.9.7] - 2026-02-19

### Added
- Public upload intake: anonymous users can upload files to a registered user via tokenized links (`/u/{token}`).
- Each account gets a personal upload URL shown in Account Settings, with a regenerate option.
- Upload form collects sender name, email, and optional message; metadata is stored on the share.
- New `Share` fields: `SenderName`, `SenderEmail`, `SenderMessage` for public upload attribution.
- New `UserAccount` fields: `UploadToken`, `UploadTokenUpdatedAtUtc` for per-account upload links.
- Rate limiting policy `PublicUploadEndpoints` for anonymous upload traffic.
- Public upload API endpoints: `/api/public-uploads/stage` and `/api/public-uploads/create-share`.
- Migration `V0902_PublicUploadLinksAndSenderMetadata`.

## [0.9.6] - 2026-02-19

### Changed
- SQL Server is now the primary database. All deployment examples and defaults updated from SQLite.
- Image gallery mosaic layout improved with natural-width tiles and vertical scrolling.
- Preview polling handles concurrent refresh requests and probes image availability before displaying.
- Encrypted archive size is now reported correctly (was previously reporting unencrypted ZIP size).
- Upload staging now correctly assigns purpose tags to share files vs template backgrounds.
- Added `ARCHITECTURE.md` with full system design documentation.
- New gallery and PDF preview screenshots added to README.

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
