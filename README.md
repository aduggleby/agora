# Agora

Agora is an ASP.NET Core 10 file sharing app for sending files with branded download pages, optional previews, optional password protection, and expiry controls.

## Features

- Upload one or many files and share with one link
- Optional password prompt before download
- Optional download-page customization (title, text, background, layout)
- Optional image and file previews for recipients
- Expiring or indefinite share links
- Download notifications (`none`, `once`, `every_time`)
- Public upload links: let anyone send files to your account via a tokenized URL with a customizable 2-64 character alphanumeric code, with a dedicated success screen after submit
- Public-upload completion emails use a dedicated "files were sent to you" template and include an on-behalf-of sender identity plus the sender message
- Account display name settings for upload pages and account menu
- Share history for signed-in uploaders, with a separate "Received" section showing shares sent via public upload (sender name, email, and message)
- Email confirmation, password reset, and account security flows
- Admin controls for system defaults
- Quick-share drag-and-drop from the dashboard with cancel support and inline limit display
- Image lightbox viewer on gallery pages with keyboard navigation
- Mobile-friendly public share pages

## Screenshots

| New Share | Download Page | Download Page Editor |
| --- | --- | --- |
| [![New share page](docs/screenshots/new-share-page.png)](docs/screenshots/new-share-page.png) | [![Download page](docs/screenshots/download-page.png)](docs/screenshots/download-page.png) | [![Download page editor](docs/screenshots/landing-page-editor.png)](docs/screenshots/landing-page-editor.png) |

| Password on Download | Image Gallery Mode | File Preview Mode |
| --- | --- | --- |
| [![Password on download](docs/screenshots/new-share-password-option.png)](docs/screenshots/new-share-password-option.png) | [![Image gallery mode](docs/screenshots/gallery-real-photos.png)](docs/screenshots/gallery-real-photos.png) | [![File preview mode](docs/screenshots/file-preview-sample-pdf.png)](docs/screenshots/file-preview-sample-pdf.png) |

## Deployment

### Container contract

Production/container deployments should use:

- Environment variables for configuration
- One writable volume mounted at `/app/data`
- Default HTTP port `18080`

All mutable runtime data should remain under `/app/data` (uploads, DataProtection keys, logs). With the default
`Storage__Provider=FileSystem`, share content lives there too; with `Storage__Provider=S3` it goes to the bucket and
`/app/data` only holds scratch (staging, drafts, `tmp/`), keys and logs (see [Storage](#storage)).

### Docker

Build image:

```bash
docker build -t agora:latest .
```

Run container:

```bash
docker run -d \
  --name agora \
  -p 18080:18080 \
  -e ConnectionStrings__Default="Server=YOUR_SQL_HOST,1433;Database=Agora;User Id=agora;Password=YOUR_PASSWORD;TrustServerCertificate=true" \
  -e Agora__PublicBaseUrl="https://files.yourdomain.com" \
  -e Email__Provider="Resend" \
  -e Email__Resend__ApiToken="<your_token>" \
  -e Email__Resend__FromDisplayName="<display_name>" \
  -e Email__Resend__FromAddress="no-reply@yourdomain.com" \
  -e Email__Resend__ApiUrl="https://api.resend.com" \
  -v agora_data:/app/data \
  agora:latest
```

### Create Database and User

Connect to SQL Server using your preferred client (Azure Data Studio, SSMS, `sqlcmd`, etc.):

```bash
# Example using sqlcmd
sqlcmd -S YOUR_SERVER_IP,1433 -U sa -P 'YOUR_SA_PASSWORD' -C
```

Run these SQL commands to create the Agora database and dedicated login:

```sql
-- Create database
CREATE DATABASE Agora;
GO

-- Create login with a strong password
CREATE LOGIN agora WITH PASSWORD = 'YourSecurePassword123!';
GO

-- Create user and grant permissions
USE Agora;
GO

CREATE USER agora FOR LOGIN agora;
GO

ALTER ROLE db_owner ADD MEMBER agora;
GO
```

Type `exit` to quit `sqlcmd`.

### Reverse proxy headers

If running behind Caddy/Nginx/Traefik, forward:

- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`

### TrueNAS SCALE (Install via YAML)

1. Create a dataset, for example `/mnt/YOUR_POOL/apps/agora/data`.
2. In `Apps -> Discover Apps`, choose `Install via YAML`.
3. Paste and adjust:

```yaml
services:
  agora:
    image: ghcr.io/aduggleby/agora:latest
    pull_policy: always
    ports:
      - "18080:18080"
    environment:
      - ConnectionStrings__Default=Server=YOUR_SQL_HOST,1433;Database=Agora;User Id=agora;Password=YOUR_PASSWORD;TrustServerCertificate=true
      - Email__Provider=Resend
      - Email__Resend__ApiToken=YOUR_RESEND_API_TOKEN
      - Email__Resend__FromDisplayName=YOUR_FROM_DISPLAY_NAME
      - Email__Resend__FromAddress=YOUR_VERIFIED_FROM_EMAIL
      - Email__Resend__ApiUrl=https://api.resend.com
      - Agora__PublicBaseUrl=https://files.YOUR_DOMAIN
    volumes:
      - /mnt/YOUR_POOL/apps/agora/data:/app/data
    restart: unless-stopped
```

## Configuration

Startup behavior:
- The app applies EF Core migrations on startup (the migration set of the selected provider).
- If migrations fail for any reason, startup logs a fatal error and the server stops.
- A missing `ConnectionStrings__Default` or an unknown `Database__Provider` stops startup with a clear error.

### Core settings

| Setting | Default | What it controls |
| --- | --- | --- |
| `ConnectionStrings__Default` | *(required)* | Database connection string (also used for Hangfire job storage) |
| `Database__Provider` | `SqlServer` | `SqlServer` or `Postgres` (case-insensitive); anything else is a startup error |
| `Agora__PublicBaseUrl` | request host | Public base URL in generated links |
| `DataProtection__KeysPath` | `<parent of StorageRoot>/keys` (`/app/data/keys` in the container) | Where DataProtection keys are persisted, so sign-ins survive restarts. Must be writable and persistent. |

### Database provider

SQL Server stays the default, so existing installs need no change. To run on PostgreSQL:

```bash
Database__Provider=Postgres
ConnectionStrings__Default="Host=YOUR_PG_HOST;Port=5432;Database=agora;Username=agora;Password=YOUR_PASSWORD;GSS Encryption Mode=Disable"
```

The database must exist; tables (and the `hangfire` schema) are created on first start.
Switching providers does not migrate data.

Token lookups are case-sensitive on PostgreSQL. Share links (`/s/{token}`) and upload links (`/u/{token}`) are matched
exactly, so `/s/MyToken` and `/s/mytoken` are different links there. On SQL Server with the default case-insensitive
collation they resolve to the same share. Generated tokens and user-chosen custom share tokens/upload codes may contain
upper- and lower-case letters, so always use links exactly as Agora shows them.

### Health endpoints

| Endpoint | Returns |
| --- | --- |
| `GET /live` | `200` while the process is up (no checks) |
| `GET /ready` | `200` when the database (and, with `Storage__Provider=S3`, the bucket) is reachable, `503` otherwise |

Both are anonymous and not rate limited.

### Logging

Logs always go to the console (stdout). In addition, a daily rolling file `agora-YYYYMMDD.log` is written:

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__Logging__File__Enabled` | `true` | `false` = stdout only (e.g. read-only root filesystem) |
| `Agora__Logging__File__Path` | `logs` (`/app/data/logs` in the container) | Log directory |
| `Agora__Logging__File__RetainedDays` | `30` | Number of daily files kept (1-3650) |

For existing installs, the legacy `Serilog__WriteTo__0__Args__path` (for example `/app/data/logs/agora-.log`) and
`Serilog__WriteTo__0__Args__retainedFileCountLimit` are still honoured and take precedence over the `Agora__Logging__File__*`
settings, so logs keep going to the same place with the same retention. As in Serilog, a legacy retention that is set but
empty means unlimited, and legacy numbers are not capped (minimum 1); the 1-3650 range applies only to `Agora__Logging__File__RetainedDays`.

### Temporary files

Large multipart form bodies are buffered to disk by ASP.NET Core (`ASPNETCORE_TEMP`). Unless `ASPNETCORE_TEMP` is set
explicitly, Agora points it at `<StorageRoot>/tmp/aspnet` (`/app/data/uploads/tmp/aspnet` in the container) so uploads
never fill a small `/tmp` (for example a size-limited tmpfs in hardened containers). Size the storage volume for the uploads in flight.

### Storage

Durable content (share files, archives, download-page backgrounds, previews) goes to an object store. Object keys are the
relative paths already stored in the database (`shares/…`, `zips/…`, `uploads/templates/…`, `previews/…`), so no
database change is involved.

| Setting | Default | What it controls |
| --- | --- | --- |
| `Storage__Provider` | `FileSystem` | `FileSystem` (content under `Agora__StorageRoot`, as before) or `S3`; anything else is a startup error |
| `Storage__S3__ServiceUrl` | *(required for S3)* | Endpoint URL, e.g. `https://hel1.your-objectstorage.com` |
| `Storage__S3__Region` | *(required for S3)* | Signing region, e.g. `hel1` |
| `Storage__S3__Bucket` | *(required for S3)* | Bucket name (must exist) |
| `Storage__S3__AccessKeyId` | *(required for S3)* | Access key |
| `Storage__S3__SecretAccessKey` | *(required for S3)* | Secret key |
| `Storage__S3__ForcePathStyle` | `false` | `false` = virtual-hosted style (Hetzner); `true` for MinIO |

Missing or invalid S3 settings stop startup. Downloads are always proxied through Agora (range requests are supported for
single files); the bucket never needs to be public.

Hetzner Object Storage:

```bash
Storage__Provider=S3
Storage__S3__ServiceUrl=https://hel1.your-objectstorage.com
Storage__S3__Region=hel1
Storage__S3__Bucket=YOUR_BUCKET
Storage__S3__AccessKeyId=YOUR_ACCESS_KEY
Storage__S3__SecretAccessKey=YOUR_SECRET_KEY
Storage__S3__ForcePathStyle=false
```

MinIO: same settings with `ServiceUrl=http://minio:9000`, any region (e.g. `us-east-1`) and `ForcePathStyle=true`.

> **Hetzner warning:** never configure a Public Access Block on the bucket. Agora does not need one (buckets are private
> by default and every download is proxied through the app), and on Hetzner it can unexpectedly change or block access
> to the bucket. Leave the bucket's access configuration untouched.

**Local scratch disk is still required in S3 mode.** Staged uploads, drafts, share-creation status, preview lock
markers and `<StorageRoot>/tmp` (zip building, `.agz` encryption/decryption, preview sources, ASP.NET upload buffers) stay
on local disk. Creating a share needs about 3× its size at peak (staged files + zip + encrypted copy), so size the
volume for **≈3× the largest share × concurrent share creations**, plus decrypted copies of password-protected archives
being downloaded. Scratch files older than `Agora__ZombieUploadRetentionHours` are swept automatically.

Switching providers does not move existing content. To move a FileSystem install to S3, copy `shares/`, `zips/`,
`uploads/templates/` and `previews/` from `StorageRoot` into the bucket with the same relative keys.

### Upgrade notes

**0.9.18:** DataProtection keys are now persisted (`DataProtection__KeysPath`) under the fixed application name `Agora`.
Before, containers kept keys only in memory, so every restart already signed everyone out. Upgrading to 0.9.18 signs all
users out (and invalidates open login/confirmation forms) one last time; after that, sign-ins survive restarts and updates.

**Security stamps:** sign-in cookies now carry a per-user security stamp that is revalidated against the database (see
"Sessions" below). Cookies issued before this change have no stamp and are rejected, so upgrading signs all users out
once. From this change on, `Production` deployments must be served over HTTPS unless `Agora__Auth__SecureCookies` is
changed (see "Sessions").

### Upload and retention

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__MaxFilesPerShare` | `20` | Maximum files per share |
| `Agora__MaxFileSizeBytes` | `5368709120` | Per-file upload limit (5 GB) |
| `Agora__MaxTotalUploadBytes` | `10737418240` | Per-share total upload limit (10 GB) |
| `Agora__DownloadEventRetentionDays` | `90` | How long download-event records are kept |
| `Agora__ZombieUploadRetentionHours` | `24` | Cleanup window for abandoned staged uploads |

### Previews

Preview and thumbnail generation decodes uploaded images and PDFs inside the app process, so it is budgeted. A source
over a budget is not decoded at all; the share shows the "preview unavailable" image for that file instead.

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__Previews__MaxSourceBytes` | `67108864` | Largest image or PDF (64 MB) that is opened for a preview |
| `Agora__Previews__MaxSourcePixels` | `50000000` | Largest image (width x height, 50 megapixels) that is decoded; checked from the file header before decoding |
| `Agora__Previews__TimeoutSeconds` | `30` | Wall-clock budget for generating one preview or thumbnail |

Not configurable: only one frame of an animated image is decoded, images are scaled down during decoding where the
format allows it, only PNG, JPEG, WEBP and BMP decoders are enabled regardless of the file's extension (GIF uploads are
served inline but get no generated preview), PNG headers are checked before decoding, PDF pages
are rasterized with the longer side at 1200 pixels (pages larger than 14400 points on a side, the PDF maximum, are
rejected) with at most two PDF renders running at once, and a preview job is retried at most once on infrastructure
errors (never on a decoder failure).

How uploaded content is served (not configurable):

- The content type of every uploaded file is derived from its file extension; the type declared by the uploading browser is ignored.
- Only raster images (`png`, `jpg`, `gif`, `webp`, `avif`, `bmp`), common video and audio formats, PDF and plain text are served inline for previews. Everything else, including HTML, SVG and XML, is always served as a download (`application/octet-stream`, `Content-Disposition: attachment`).
- All responses carrying user content (files, archive downloads, backgrounds, previews, thumbnails, link-preview images) are sent with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox` (inline PDFs are exempt from the CSP so the browser's PDF viewer can render them).
- Download-page background images must be JPG, PNG or WEBP. SVG backgrounds are no longer accepted; previously uploaded SVG backgrounds are offered as a download instead of being displayed.

### Sessions

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__Auth__SessionLifetimeDays` | `14` | Sliding lifetime of the sign-in cookie: renewed while the user stays active, expired after this many idle days |
| `Agora__Auth__SessionRevalidationMinutes` | `5` | How often a signed-in session is checked against the user record; `0` checks on every request |
| `Agora__Auth__SecureCookies` | `Auto` | When the sign-in and CSRF cookies get the `Secure` flag: `Auto` (always in `Production`, only on HTTPS requests elsewhere), `Always`, `SameAsRequest` |

Every sign-in cookie carries the user's security stamp. The stamp changes when the password is changed or reset, an
email address change is confirmed, the role changes, or the account is disabled or re-enabled. The cookie is compared
with the database at most every `SessionRevalidationMinutes`, so after any of those events (or a deletion) every
session of that user is signed out within that interval. A promoted or demoted user therefore has to sign in again
and gets the new role at that sign-in. Signing in does not end the user's other sessions. Open share-progress
(SignalR) connections are checked the same way on connect and on every call.

With `SecureCookies=Auto`, `Production` (the container default) marks the cookies `Secure`, so the app must be reached
over HTTPS, typically behind a reverse proxy that forwards `X-Forwarded-Proto` (see "Reverse proxy headers"). Plain
HTTP works outside `Production`, for example with `ASPNETCORE_ENVIRONMENT=Development`.

> **Warning:** `Agora__Auth__SecureCookies=SameAsRequest` exists for HTTP-only installs on a trusted private network.
> On a site reachable over plain HTTP from the public internet it lets anyone on the network path read the session
> and CSRF cookies and take over the account. Prefer HTTPS.

### Email

| Setting | Default | What it controls |
| --- | --- | --- |
| `Email__Provider` | `Resend` | Email provider mode |
| `Email__Resend__ApiToken` | none | API token for provider |
| `Email__Resend__FromDisplayName` | empty | Sender display name |
| `Email__Resend__FromAddress` | none | Sender address (must be verified) |
| `Email__Resend__ApiUrl` | `https://api.resend.com` | API base URL override |

## Local Development

Prerequisites:

- .NET SDK 10+
- Node.js 20+
- Docker (used by `run-dev.sh`)
- tmux (used by `run-dev.sh`)

Start local dev environment:

```bash
./run-dev.sh
```

Stop local dev environment:

```bash
./stop-dev.sh
```

## Build (ANDO)

`Agora` includes `build.csando` for pipeline-style builds.

```bash
ando run --dind
```

Learn more about ANDO: [andobuild.com](https://andobuild.com)
