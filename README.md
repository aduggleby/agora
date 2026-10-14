# Agora

Agora is a self-hosted ASP.NET Core 10 file sharing app: upload files, send one link, and let recipients download
from a branded download page with optional previews, password protection and expiry. It runs as a single container
with one data volume, a SQL Server or PostgreSQL database, and optionally an S3-compatible bucket for the content.

## Features

- Upload one or many files and share them with one link (`/s/{token}`), with custom link tokens if you want them
- Expiring or indefinite share links (1 hour to 1 year, or never); expired shares can be re-enabled for 24 hours
- Download notifications by email (`none`, `once`, `every_time`), optionally with the downloader's city and country
- Download pages with a per-account template: title, text, background image, card position
- Gallery and preview modes: an image mosaic with a lightbox for image-only shares, file-by-file previews
  (images, PDF first page) for mixed shares, or a plain download page
- Password-protected archives: the zip is encrypted at rest and decrypted only for a correct password
- Public upload links (`/u/{code}`): anyone can send files to your account without signing in, with server-side quotas
- Temporary direct links: one image, video, audio file, PDF or text file served raw at `/s/{token}` for 30 minutes
  to 7 days, for chats, forums or `<img src>`
- Share history with a separate "Received" section for files that arrived through your upload link
- Accounts with email confirmation, password reset, display name and per-account share defaults
- Admin page (`/admin`): manage users and roles, enable or disable accounts, switch registration off
- Health endpoints (`/live`, `/ready`) and a Hangfire dashboard (`/hangfire`) for admins
- Two database providers (SQL Server, PostgreSQL) and two storage providers (local file system, S3-compatible)
- Mobile-friendly public pages, quick-share drag-and-drop from the dashboard

## Screenshots

| New Share | Download Page | Download Page Editor |
| --- | --- | --- |
| [![New share page](docs/screenshots/new-share-page.png)](docs/screenshots/new-share-page.png) | [![Download page](docs/screenshots/download-page.png)](docs/screenshots/download-page.png) | [![Download page editor](docs/screenshots/landing-page-editor.png)](docs/screenshots/landing-page-editor.png) |

| Password on Download | Image Gallery Mode | File Preview Mode |
| --- | --- | --- |
| [![Password on download](docs/screenshots/new-share-password-option.png)](docs/screenshots/new-share-password-option.png) | [![Image gallery mode](docs/screenshots/gallery-real-photos.png)](docs/screenshots/gallery-real-photos.png) | [![File preview mode](docs/screenshots/file-preview-sample-pdf.png)](docs/screenshots/file-preview-sample-pdf.png) |

## Quick start with Docker

The image is published as `ghcr.io/aduggleby/agora:<version>` (for example `ghcr.io/aduggleby/agora:0.9.26`) and
`ghcr.io/aduggleby/agora:latest`. Pin a version in production and read the [upgrade notes](#upgrade-notes) before
moving to a newer one. The container:

- listens on port `18080` (`ASPNETCORE_URLS=http://0.0.0.0:18080`), runs with `ASPNETCORE_ENVIRONMENT=Production`
- is configured entirely through environment variables (`Section__Key` form, see the [settings reference](#settings-reference))
- keeps all mutable data under one volume, `/app/data`: scratch and (with the default file-system storage) the
  share content under `/app/data/uploads`, DataProtection keys under `/app/data/keys`, logs under `/app/data/logs`
- runs as the unprivileged `app` user (UID 1654). A named volume inherits the right ownership from the image; a bind
  mount must be owned by UID 1654 on the host before the first start (`sudo chown -R 1654:1654 /path/on/host`)

Three settings are mandatory or close to it:

- `ConnectionStrings__Default` (and `Database__Provider=Postgres` for PostgreSQL): startup fails without a connection string.
- `Agora__PublicBaseUrl`: the public origin (`https://files.example.com`), used for every link that leaves the browser.
  Startup fails without it (only `Development` and `E2E` fall back to the request host).
- A working email setup: new accounts, including the first admin, must confirm their address before they can sign in.
  With `Email__Resend__ApiToken` empty the app starts but drops every email with a warning in the log. For a first
  test without an email provider, set `Email__Provider=filesystem`: each email is written as a JSON file under
  `/app/data/emails`, and the confirmation link is in its `ActionUrl` field.

### PostgreSQL (recommended)

```yaml
services:
  agora:
    image: ghcr.io/aduggleby/agora:0.9.26
    ports:
      - "18080:18080"
    environment:
      Database__Provider: Postgres
      ConnectionStrings__Default: "Host=db;Port=5432;Database=agora;Username=agora;Password=CHANGE_ME;SSL Mode=Disable"
      Agora__PublicBaseUrl: https://files.example.com
      # The reverse proxy's address or network; without it every visitor shares the proxy's IP (see "Reverse proxy").
      Agora__TrustedProxies: 172.28.0.0/16
      AllowedHosts: files.example.com
      # Cookies are Secure in Production, so the site must be reached over HTTPS through the proxy.
      # Agora__Auth__SecureCookies: SameAsRequest   # only for an HTTP-only install on a private network
      Email__Provider: resend
      Email__Resend__ApiToken: CHANGE_ME
      Email__Resend__FromAddress: no-reply@example.com
      Email__Resend__FromDisplayName: Agora
    volumes:
      - agora_data:/app/data
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  db:
    image: postgres:17
    environment:
      POSTGRES_DB: agora
      POSTGRES_USER: agora
      POSTGRES_PASSWORD: CHANGE_ME
    volumes:
      - agora_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U agora -d agora"]
      interval: 5s
      timeout: 5s
      retries: 20
    restart: unless-stopped

volumes:
  agora_data:
  agora_db:
```

`POSTGRES_USER` makes `agora` the owner of the database, which is all the rights the app needs
(see [Database hosting](#database-hosting)). For a database on another host use `SSL Mode=Require` (or
`VerifyFull` with a trusted certificate) and add `GSS Encryption Mode=Disable` if the connection stalls or fails while
the client tries GSSAPI encryption first.

### SQL Server

```yaml
services:
  agora:
    image: ghcr.io/aduggleby/agora:0.9.26
    ports:
      - "18080:18080"
    environment:
      Database__Provider: SqlServer
      ConnectionStrings__Default: "Server=db,1433;Database=Agora;User Id=agora;Password=CHANGE_ME;Encrypt=True;TrustServerCertificate=True"
      Agora__PublicBaseUrl: https://files.example.com
      Agora__TrustedProxies: 172.28.0.0/16
      AllowedHosts: files.example.com
      Email__Provider: resend
      Email__Resend__ApiToken: CHANGE_ME
      Email__Resend__FromAddress: no-reply@example.com
      Email__Resend__FromDisplayName: Agora
    volumes:
      - agora_data:/app/data
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  db:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      ACCEPT_EULA: "Y"
      MSSQL_SA_PASSWORD: CHANGE_ME_Strong1!
    volumes:
      - agora_mssql:/var/opt/mssql
    healthcheck:
      test: ["CMD-SHELL", "/opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P \"$$MSSQL_SA_PASSWORD\" -Q 'SELECT 1' || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 30
    restart: unless-stopped

volumes:
  agora_data:
  agora_mssql:
```

Create the database and the `agora` login once before the first start (see
[SQL Server login and connection string](#sql-server-login-and-connection-string) below; with the bundled container,
run the SQL through `docker compose exec db /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P '...'`). The
example connects with a dedicated login rather than `sa`. If the app starts before the database answers, the
migration fails and the container restarts until it does.

### First sign-in

Open the site, register an account and confirm the address from the email. The first account that registers becomes
the admin; everyone after that is a regular user. Registration is open by default; switch it off on `/admin` once your
users are in. There is no admin-side user creation, so have everyone register before you close registration.

### Bind mounts, TrueNAS and other hosts

A bind mount (for example a TrueNAS dataset) mounted at `/app/data` must be owned by UID/GID 1654 before the first
start: set the dataset's owner to that numeric id, or run `chown -R 1654:1654` on the directory. Installs that ran an
image older than 0.9.22 (which ran as root) must apply the same `chown` once before upgrading.

TrueNAS SCALE accepts the compose files above as-is under `Apps -> Discover Apps -> Install via YAML`; replace the
named `agora_data` volume with the dataset path (`/mnt/YOUR_POOL/apps/agora/data:/app/data`) and point the connection
string at your database.

## Database hosting

`Database__Provider` selects the provider: `SqlServer` (the default when the setting is empty) or `Postgres`, matched
case-insensitively; any other value stops startup. `ConnectionStrings__Default` is used for both EF Core and the
Hangfire job storage, so Hangfire's tables live in the same database. Switching providers does not migrate data.

### PostgreSQL role and connection string

```text
Database__Provider=Postgres
ConnectionStrings__Default=Host=db.example.com;Port=5432;Database=agora;Username=agora;Password=...;SSL Mode=Require
```

Keys follow the Npgsql connection string format. `SSL Mode` is `Disable`, `Prefer`, `Require`, `VerifyCA` or
`VerifyFull`. Add `GSS Encryption Mode=Disable` when the client stalls or fails negotiating GSSAPI encryption before
falling back to TLS (the e2e suite sets it for its local container). Create the database and role, with the role as
owner:

```sql
CREATE ROLE agora LOGIN PASSWORD '...';
CREATE DATABASE agora OWNER agora;
```

At startup Agora creates its tables and `__EFMigrationsHistory` in the default schema and Hangfire creates its own
`hangfire` schema, so the role must be allowed to create schemas and tables: make it the database owner, or grant it
`CREATE` on the database and on the schema it migrates into. Token lookups are case-sensitive on PostgreSQL: `/s/MyToken`
and `/s/mytoken` are different links (on SQL Server with the default collation they resolve to the same share), so
always use links exactly as Agora shows them.

### SQL Server login and connection string

```text
Database__Provider=SqlServer
ConnectionStrings__Default=Server=db.example.com,1433;Database=Agora;User Id=agora;Password=...;Encrypt=True;TrustServerCertificate=True
```

Create the database and a dedicated login (`sqlcmd -S db.example.com,1433 -U sa -P '...' -C`):

```sql
CREATE DATABASE Agora;
GO
CREATE LOGIN agora WITH PASSWORD = 'YourSecurePassword123!';
GO
USE Agora;
GO
CREATE USER agora FOR LOGIN agora;
GO
ALTER ROLE db_owner ADD MEMBER agora;
GO
```

`db_owner` covers what startup needs: creating the tables and `__EFMigrationsHistory` in `dbo` and the `HangFire`
schema. Drop `TrustServerCertificate=True` once the server presents a certificate the container trusts.

### Migrations and upgrades

- Agora applies its EF Core migrations at every start (the migration set of the selected provider:
  `Migrations/` for SQL Server, `Migrations/Postgres/` for PostgreSQL). The two sets are generated together with
  `scripts/add-migration.sh` and always describe the same schema. If a migration fails, startup logs a critical error
  and the process exits, so a failed upgrade never runs on a half-migrated schema. There are no down migrations in
  normal operation: take a database backup before upgrading, and restore it (together with the previous image) to
  roll back.
- Hangfire prepares or upgrades its own schema on every start.
- Some releases run a one-time data step after the migrations: 0.9.22 stamps every share and download-page template
  with the id of the account registered under its uploader address (`OwnerUserId`), records the completion in
  `SystemSettings` (`ownership.backfill_completed_at`) and never runs again. Rows that match no account at that
  moment are reachable by nobody; the startup log reports their number.
- Two releases sign every user out once because the session format changed: 0.9.18 (keys are persisted from then on)
  and 0.9.20 (security stamps). Ordinary upgrades keep sessions.
- The database must exist before the first start when the login cannot create databases (a least-privilege login
  usually cannot); with sufficient rights EF Core creates it.

### Backups

Back up three things together: the database (`pg_dump` or `BACKUP DATABASE`), the data volume `/app/data` (with
`Storage__Provider=FileSystem` it holds the share content; in every mode it holds the DataProtection keys under
`keys/`, without which every session and every pending confirmation link becomes invalid) and, in S3 mode, the
bucket. Scratch directories under `/app/data/uploads` (`uploads/staged*`, `uploads/drafts`, `tmp/`) and `logs/` can be
excluded.

## Storage

Durable content (share files, archives, download-page backgrounds, previews and link-preview images) is written
through an object store selected by `Storage__Provider`:

- `FileSystem` (default): everything under `Agora__StorageRoot` (`/app/data/uploads` in the container).
- `S3`: an S3-compatible bucket; `/app/data` then only holds scratch, keys and logs.

Object keys are the relative paths that are stored in the database (`shares/...`, `zips/...`, `uploads/templates/...`,
`previews/...`), so switching the provider involves no database change, but it does not move existing content: to move
a FileSystem install to S3, copy those four directories from `StorageRoot` into the bucket with the same relative keys.

| Setting | Default | What it controls |
| --- | --- | --- |
| `Storage__Provider` | `FileSystem` | `FileSystem` or `S3` (case-insensitive); anything else is a startup error |
| `Storage__S3__ServiceUrl` | *(required for S3)* | Endpoint URL, for example `https://s3.example.com` or `http://minio:9000`; must be an absolute http(s) URL |
| `Storage__S3__Region` | *(required for S3)* | Signing region (whatever your provider documents; MinIO accepts any value such as `us-east-1`) |
| `Storage__S3__Bucket` | *(required for S3)* | Bucket name; the bucket must exist |
| `Storage__S3__AccessKeyId` | *(required for S3)* | Access key |
| `Storage__S3__SecretAccessKey` | *(required for S3)* | Secret key |
| `Storage__S3__ForcePathStyle` | `false` | `false` = virtual-hosted style URLs (bucket as a subdomain, as Hetzner Object Storage and AWS use); `true` = path style (MinIO) |

Missing or invalid S3 settings stop startup. `GET /ready` lists the bucket (cached for 30 seconds when healthy).
Downloads are always proxied through Agora with range support for single files, so the bucket never needs to be
public: keep it private and do not add a public-access block, bucket policy or ACL for Agora's sake. On some
providers a public-access block changes or breaks access for the credentials themselves, so leave the bucket's access
configuration untouched.

Example for a MinIO container on the same compose network:

```text
Storage__Provider=S3
Storage__S3__ServiceUrl=http://minio:9000
Storage__S3__Region=us-east-1
Storage__S3__Bucket=agora
Storage__S3__AccessKeyId=...
Storage__S3__SecretAccessKey=...
Storage__S3__ForcePathStyle=true
```

### Scratch space and sizing

Local disk under `StorageRoot` is needed in every mode. It holds staged uploads, drafts, share-creation status files,
preview lock markers and `tmp/` (archive building, `.agz` encryption and decryption, preview sources, and the ASP.NET
multipart buffers under `tmp/aspnet`, where `ASPNETCORE_TEMP` points unless you set it yourself). Files in scratch are
swept after `Agora__ZombieUploadRetentionHours`.

Before a request body is read, Agora checks that the scratch area stays below `Agora__Scratch__MaxBytes` (when set)
and that at least `Agora__Scratch__MinFreeBytes` remain free on the volume afterwards; the demand stays reserved while
the upload is written or the archive is built, and a request that does not fit is refused with `507 Insufficient
Storage`. What a share reserves on top of its staged originals (which are already in scratch):

- FileSystem: the scratch zip (1x the share size), plus an encrypted copy (1x) for a password-protected share, plus the
  durable originals and archive (2x) on the same volume. Budget up to 4x the largest share while it is created (5x
  with a password); afterwards 2x stays as durable content.
- S3: only the scratch zip (1x) and, with a password, the encrypted copy (1x). Budget 2x to 3x the largest share per
  share being created.

Multiply by the number of shares created at the same time, and add room for decrypted copies of password-protected
archives being downloaded. Each stage request is capped at `Agora__MaxFileSizeBytes` plus 1 MB and reserves that
buffer before the body is read, so the ASP.NET buffering costs at most `MaxFileSizeBytes x concurrent uploads` on top.

## Reverse proxy and security

### Reverse proxy headers

Run Agora behind a TLS-terminating proxy (Caddy, Nginx, Traefik) that sends `X-Forwarded-For`, `X-Forwarded-Proto`
and `X-Forwarded-Host`, and list the proxy in `Agora__TrustedProxies`: IP addresses and CIDR networks separated by
commas (semicolons or whitespace work too), for example `10.0.0.5,172.28.0.0/16`. Loopback is always trusted;
forwarded headers from any other peer are ignored. An entry that is neither an address nor a network stops startup.

With the setting empty, a proxy on a Docker network makes every client look like the proxy's address: download
notifications record the proxy, lockouts and the per-IP limiters treat all visitors as one client, and a busy public
instance starts answering `429` once the anonymous budget (`Agora__RateLimits__AnonymousPerMinute`, 1200/min) is
used up. Startup logs a warning in that state. Only the last `X-Forwarded-For` entry is used, so a proxy that appends
to a client-supplied list is fine, but the proxy must set `X-Forwarded-Host` and `X-Forwarded-Proto` from its own view
of the request and the app must not be reachable except through the proxy. `ASPNETCORE_FORWARDEDHEADERS_ENABLED` is
unnecessary and harmless: Agora configures the forwarded-headers middleware itself and resets the trusted lists, so
that variable cannot widen the trust to every peer.

### Public base URL and allowed hosts

Links that leave the browser (emails, share and upload links, Open Graph tags) are built from `Agora__PublicBaseUrl`
only, never from the request host, so a spoofed `Host` or `X-Forwarded-Host` header cannot redirect a password-reset
link. The value must be an absolute http(s) origin without path, query or fragment; anything else is a startup error.

`AllowedHosts` defaults to `*`, which serves any `Host` header. Set it to the public hostname(s) in production
(`AllowedHosts=files.example.com`, several separated by `;`) and configure the proxy to forward only those names.
Startup logs a warning in `Production` while the value is `*`.

### Cookies and sessions

Sign-in and CSRF cookies are `HttpOnly` and `SameSite=Lax`. Whether they also get the `Secure` flag is controlled by
`Agora__Auth__SecureCookies`: `Auto` (always in `Production`, only on HTTPS requests elsewhere), `Always` or
`SameAsRequest`. With the container default (`Production`, `Auto`) the site must be reached over HTTPS, which behind
a proxy means the proxy is listed in `Agora__TrustedProxies` and sends `X-Forwarded-Proto: https`; over plain HTTP the
browser never sends the cookies back and nobody can sign in.

> **Warning:** `Agora__Auth__SecureCookies=SameAsRequest` exists for HTTP-only installs on a trusted private network.
> On a site reachable over plain HTTP from the internet it lets anyone on the network path read the session and CSRF
> cookies and take over the account. Prefer HTTPS.

The sign-in cookie slides: it is renewed while the user is active and expires after `Agora__Auth__SessionLifetimeDays`
idle days (14). It carries the user's security stamp, which changes on password change or reset, confirmed email
change, role change, and disable or re-enable. The cookie is checked against the database at most every
`Agora__Auth__SessionRevalidationMinutes` (5; `0` checks every request), so after any of those events, or a deletion,
every session of that user ends within that interval; a promoted or demoted user signs in again and gets the new role
then. SignalR connections are checked the same way. Signing in does not end the user's other sessions.

### Security headers

Unless `Agora__SecurityHeaders__Enabled=false` (only when the proxy sets these itself), every response carries:

| Header | Value |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains`, only on HTTPS requests |

A header the response already carries is left alone, so the enforced `Content-Security-Policy` of user-content
responses is never replaced. The app's own HTML pages additionally get a `Content-Security-Policy-Report-Only` header
with a per-request script nonce:

```text
default-src 'self'; script-src 'self' 'nonce-<random>'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; font-src 'self' https://fonts.gstatic.com;
frame-ancestors 'self'; form-action 'self'; base-uri 'self'; object-src 'none'
```

Report-only means the browser blocks nothing and only logs what an enforced policy would have blocked. All scripts
are bundled locally (SignalR and Alpine included) and every `<script>` tag carries the nonce; Google Fonts is the only
third-party origin. Known reports today are inline `onclick` handlers on the download page's lightbox and the Alpine
expressions on the "share created" page. The Hangfire dashboard serves its own inline scripts and gets no report-only
policy. To see the reports, open the browser developer tools, load a page and look in the console for messages
starting with "[Report Only]" (Chrome, Edge) or "Content-Security-Policy: The page's settings would block" (Firefox).

### How uploaded content is served

- The content type of every uploaded file is derived from its file extension; the type declared by the uploading
  browser is ignored.
- Only raster images (`png`, `jpg`, `gif`, `webp`, `avif`, `bmp`), common video (`mp4`, `m4v`, `webm`, `mov`, `ogv`)
  and audio (`mp3`, `wav`, `ogg`, `oga`, `m4a`, `aac`, `flac`, `weba`) formats, PDF and plain text (`txt`, `log`)
  are served inline. Everything else, including HTML, SVG and XML, is always served as a download
  (`application/octet-stream`, `Content-Disposition: attachment`).
- Every response carrying user content (files, archives, backgrounds, previews, thumbnails, link-preview images) is
  sent with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`
  (inline PDFs are exempt from the CSP so the browser's PDF viewer can render them).
- Download-page background images must be JPG, PNG or WEBP. SVG backgrounds are not accepted; SVG backgrounds uploaded
  by older versions are offered as a download instead of being displayed.

### Rate limits

Every limiter keys on the client address as seen after the forwarded-headers middleware (so `Agora__TrustedProxies`
matters). Rejected requests get `429` with a `Retry-After` header.

| Scope | Limit |
| --- | --- |
| Anonymous requests, site-wide, per IP | `Agora__RateLimits__AnonymousPerMinute` (1200/min, sliding window; `0` disables) |
| Signed-in requests, per account | 120/min |
| Sign-in, registration, password reset, resend and confirmation handlers, per IP | 10/min |
| Public uploads (`/api/public-uploads/*`), per IP | 25/min |
| Single-file and archive downloads, the preview "retry" button and link-preview images, per share and IP | 20/min (preview, thumbnail and status polling only count against the anonymous budget) |

Health endpoints and static files are exempt. Sizing the anonymous budget: a download page with 20 files whose previews
are still being generated polls about 480 requests/min, so the default leaves room for two such pages behind one
address (an office NAT counts as one client).

### Accounts and passwords

- Newly chosen passwords are 8 to 128 characters (length is the only rule); existing passwords of any length keep
  working. Hashes use PBKDF2-HMAC-SHA256 with 600,000 iterations in a versioned format; hashes from earlier versions
  (100,000 iterations) are upgraded in place at the next sign-in.
- Sign-in failures are uniform ("Invalid credentials.") and cost the same password verification whether the address is
  unknown, the password is wrong or the account is disabled or locked. Only the correct password for an unconfirmed
  account leads to the "confirm your email" page.
- Lockout is per account and client address: 5 wrong passwords for one account from one address within 15 minutes
  refuse that address for that account for 15 minutes, silently; other addresses with the correct password still sign
  in. The state lives in process memory (one instance; a restart clears it). Per-account failure counters stay
  visible to admins.
- Registration always answers "check your email". An unconfirmed address is claimed by the newest registrant (their
  password becomes the active one, the earlier confirmation link stops working), so only whoever controls the mailbox
  can activate the account. A confirmed address gets a notice that it is already registered.
- Emailed links (`/auth/confirm-email`, `/auth/confirm-email-change`, `/auth/confirm-password-change`, password reset)
  open a page with a confirm button; the action runs on that CSRF-protected POST, so mail scanners and link previews
  cannot use up the token. Every such link answers one "invalid or expired" message whether the address is unknown,
  the token is wrong or the link was already used.
- Any credential change (password change confirmed, password reset, email change confirmed) rotates the security
  stamp and invalidates every pending token of the account. A confirmed email change is reported to both addresses.
- Shares and the download-page template belong to the account id, never to the email address: they stay with the
  account through an email change, deleting a user deletes its shares and template, and a later account registered
  under a freed address inherits nothing.
- Admins cannot demote, disable or delete the last enabled admin, nor their own account from the admin forms.

### What the app logs

Logs go to stdout and, unless disabled, a daily rolling file (see [Logs](#logs)). Startup logs the chosen providers,
the log path and retention, the public base URL and the trusted-proxy list; requests log on errors; download events
(address, user agent, browser and OS family) are stored in the database for notifications and the share details and
deleted after `Agora__DownloadEventRetentionDays`. With `Agora__GeoLookup__Enabled=true` (the default) the
downloader's public IP address is sent to the third-party service `https://ipwho.is/` to show city and country in
notification emails; set it to `false` to keep downloader addresses in-house.

Share, upload and confirmation tokens never appear in Agora's own log lines (they are referenced by a short hash), and
a Serilog enricher rewrites `/s/{token}`, `/u/{token}`, `/shares/created/{token}` and `token=` values in every string
property of a log event (request paths, redirect targets) to that reference. The framework's per-request "Request
starting/finished" lines would print full URLs including such tokens, so they are off by default
(`Serilog__MinimumLevel__Override__Microsoft.AspNetCore.Hosting.Diagnostics=Warning` in `appsettings.json`); re-enable
them only with a sink you treat as sensitive. Passwords, the email API token, S3 keys and the connection string are
not written to the log.

## Settings reference

Every setting can be given as an environment variable (`Section__Key`) or in `appsettings.json`. Defaults are the
code defaults; the "Container" column shows what the image's `Dockerfile` sets on top.

### Startup checks

Startup stops with a clear error on: a missing `ConnectionStrings__Default`, an unknown `Database__Provider` or
`Storage__Provider`, missing or invalid `Storage__S3__*` settings in S3 mode, a missing or invalid
`Agora__PublicBaseUrl` (outside `Development`/`E2E`), an invalid `Agora__TrustedProxies` entry, or a failed migration.
In `Production` it warns when `Agora__TrustedProxies` is empty or `AllowedHosts` is `*`.

### Host and database

| Setting | Default | Container | What it controls |
| --- | --- | --- | --- |
| `ASPNETCORE_URLS` | Kestrel default | `http://0.0.0.0:18080` | Listening address |
| `ASPNETCORE_ENVIRONMENT` | `Production` | `Production` | `Development` enables the dev user and runtime Razor compilation; `E2E` is for the test suite only |
| `ASPNETCORE_TEMP` | `<StorageRoot>/tmp/aspnet` (set by Agora when unset) | same | Where ASP.NET buffers multipart bodies larger than 64 KB |
| `AllowedHosts` | `*` | same | Host names the app answers for (`files.example.com;admin.example.com`); `*` serves any `Host` header |
| `ConnectionStrings__Default` | *(required)* | | Database connection string (EF Core and Hangfire) |
| `Database__Provider` | `SqlServer` | | `SqlServer` or `Postgres` (case-insensitive) |
| `DataProtection__KeysPath` | `keys` next to the `StorageRoot` directory | `/app/data/keys` | Where DataProtection keys are persisted (sign-in cookies, CSRF and emailed-link tokens); must be writable and persistent |

### `Agora__*` core

| Setting | Default | Container | What it controls |
| --- | --- | --- | --- |
| `Agora__PublicBaseUrl` | *(required outside Development/E2E)* | | Public origin (`https://host[:port]`, no path) for every link that leaves the browser |
| `Agora__TrustedProxies` | empty (loopback only) | | Reverse proxies whose `X-Forwarded-For/Proto/Host` are honoured: IP addresses and CIDR networks, comma separated |
| `Agora__StorageRoot` | `storage` | `/app/data/uploads` | Scratch root and, with `Storage__Provider=FileSystem`, the durable content root |
| `Agora__MaxFilesPerShare` | `20` | | Maximum files per share, enforced while files are staged |
| `Agora__MaxFileSizeBytes` | `5368709120` (5 GB) | | Per-file upload limit; also caps one stage request (plus 1 MB of form overhead) |
| `Agora__MaxTotalUploadBytes` | `10737418240` (10 GB) | | Per-share total, enforced per draft while staging; also bounds the multipart body of `POST /api/shares` (plus 1 MB) |
| `Agora__DownloadEventRetentionDays` | `90` | | How long download-event records are kept |
| `Agora__ZombieUploadRetentionHours` | `24` | | Age after which abandoned staged uploads, drafts of signed-in users, share-creation status files, `tmp/` files and preview `.lock` markers are swept; also the shortest interval at which a polling download page can re-queue a missing preview |

### `Agora__Auth__*`

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__Auth__SessionLifetimeDays` | `14` | Sliding lifetime of the sign-in cookie |
| `Agora__Auth__SessionRevalidationMinutes` | `5` | How often a session is checked against the user record; `0` = every request |
| `Agora__Auth__SecureCookies` | `Auto` | `Auto` (Secure always in `Production`, on HTTPS requests elsewhere), `Always`, `SameAsRequest` |

### `Agora__RateLimits__*`, `Agora__GeoLookup__*`, `Agora__SecurityHeaders__*`

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__RateLimits__AnonymousPerMinute` | `1200` | Site-wide requests per minute for one anonymous client (by IP); `0` disables this budget. The other limits are fixed (see [Rate limits](#rate-limits)) |
| `Agora__GeoLookup__Enabled` | `true` | Send the downloader's IP address to `https://ipwho.is/` to show city and country in notifications; `false` shows the bare address |
| `Agora__SecurityHeaders__Enabled` | `true` | Browser hardening headers and the report-only CSP; `false` only when the proxy sets them |

### `Agora__Scratch__*`

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__Scratch__MaxBytes` | `0` (unlimited) | High-water mark for the scratch area (`uploads/staged*`, `uploads/drafts`, `tmp`); the size is re-measured at most every 30 s |
| `Agora__Scratch__MinFreeBytes` | `1073741824` (1 GB) | Free space that must remain on the `StorageRoot` volume after a request; `0` disables the check |

### `Agora__PublicUploads__*`

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__PublicUploads__MaxOpenDraftsPerToken` | `20` | Drafts one upload code may have open at once (files staged but not submitted, younger than the draft retention) |
| `Agora__PublicUploads__MaxOpenDraftsPerIp` | `10` | Open drafts one client IP may have across all upload codes (addresses are indexed as SHA-256 hashes) |
| `Agora__PublicUploads__DraftRetentionHours` | `6` | How long an anonymous draft and its staged files are kept after the last activity; an idle draft no longer counts as open |
| `Agora__PublicUploads__MaxSharesPerCodePerDay` | `50` | Received shares one account may get through its upload link in any 24 hour window; `0` disables |
| `Agora__PublicUploads__MaxBytesPerCodePerDay` | `21474836480` (20 GB) | Bytes of received shares per account in any 24 hour window; `0` disables. Both daily budgets are per account, so rotating the code does not reset them |
| `Agora__PublicUploads__DefaultExpiryDays` | `30` | Expiry of a received share when the owner's default expiry cannot be resolved (every account has one, 7 days unless changed, so this is a fallback) |

### `Agora__Previews__*`

| Setting | Default | What it controls |
| --- | --- | --- |
| `Agora__Previews__MaxSourceBytes` | `67108864` (64 MB) | Largest image or PDF that is opened for a preview |
| `Agora__Previews__MaxSourcePixels` | `50000000` (50 MP) | Largest image (width x height) that is decoded, checked from the file header |
| `Agora__Previews__TimeoutSeconds` | `30` | Wall-clock budget for one preview or thumbnail |

### `Agora__Logging__File__*`

| Setting | Default | Container | What it controls |
| --- | --- | --- | --- |
| `Agora__Logging__File__Enabled` | `true` | | `false` = stdout only (for example with a read-only root filesystem) |
| `Agora__Logging__File__Path` | `logs` | `/app/data/logs` | Log directory |
| `Agora__Logging__File__RetainedDays` | `30` | | Number of daily files kept (clamped to 1-3650) |

### `Storage__*`

See the table in [Storage](#storage).

### `Email__*`

| Setting | Default | Container | What it controls |
| --- | --- | --- | --- |
| `Email__Provider` | `resend` | | `filesystem` writes emails to disk; any other value (case-insensitive) uses the Resend-compatible API |
| `Email__Resend__ApiToken` | empty | empty | Bearer token; while empty every email is skipped with a warning |
| `Email__Resend__ApiUrl` | `https://api.resend.com` | same | API base URL; emails are posted to `<ApiUrl>/emails` |
| `Email__Resend__FromAddress` | `no-reply@example.com` | same | Sender address (must be verified with the provider) |
| `Email__Resend__FromDisplayName` | empty | | Sender display name |
| `Email__FileSystem__OutputDirectory` | `emails` | `/app/data/emails` | Directory for the `filesystem` provider |

### Legacy and pass-through

| Setting | What it controls |
| --- | --- |
| `Serilog__MinimumLevel__*` | Log levels; the `Serilog` section is read for levels, overrides and enrichers (sinks are configured by Agora) |
| `Serilog__WriteTo__0__Args__path`, `Serilog__WriteTo__0__Args__retainedFileCountLimit` | Pre-0.9.18 file-sink settings, still honoured and taking precedence over `Agora__Logging__File__Path`/`RetainedDays`; a legacy retention that is set but empty means unlimited |

## Email

Agora sends emails for account confirmation, password and email changes, password reset, download notifications and
received public uploads. The provider is chosen by `Email__Provider`:

- `resend` (default, or any value other than `filesystem`): a Resend-compatible JSON API. Agora posts
  `{from, to, subject, html}` to `<Email__Resend__ApiUrl>/emails` with `Authorization: Bearer <Email__Resend__ApiToken>`.
  Any service that accepts that request shape works by pointing `ApiUrl` at it. While the token is empty the app
  starts normally but drops every email with a warning in the log.
- `filesystem`: every email is written as a JSON file (`yyyyMMdd-HHmmssfff-<guid>.json`, including the recipient,
  subject, HTML body and the action link) to `Email__FileSystem__OutputDirectory`. Meant for development and for a
  first local test; the e2e suite and `run-dev.sh` use it.

## Public upload links and temporary direct links

### Public upload links

Every account has an upload link `/u/<code>` (Account > Settings) that anyone can use to send files to that account
without signing in. The sender fills in a name, an email address and an optional message, which the owner sees in the
"Received" section of the dashboard and in the "files were sent to you" notification email. Generated codes are 12
alphanumeric characters; a custom code must be 8 to 64 letters or digits (codes set before this minimum existed keep
working until they are changed). Regenerating the code invalidates the old link.

Received shares use the owner's default expiry (Account > Share defaults; 7 days unless changed, "indefinite" only when
the owner chose it there) and count toward the owner's quotas. Everything is enforced server-side: the per-file and
per-share limits, the open-draft caps per code and per client address, the daily count and byte budgets per account,
the shorter anonymous draft retention and the 25/min per-IP limiter (see [`Agora__PublicUploads__*`](#agora__publicuploads__)).

### Temporary direct links

On the new-share page a signed-in user who has staged exactly one file can create a **temporary direct link** instead
of a share link. The link uses the normal `/s/{token}` format, but opening it returns the file itself (an image shows as
an image, a PDF as a PDF) with the usual user-content headers (`nosniff`, sandbox CSP), so it can be pasted into chats,
forums or an `<img src>`.

- Eligible files are the ones the content policy serves inline: raster images, common video and audio, PDF and plain
  text. Other types keep the button disabled with the reason as a tooltip.
- Durations are fixed: 30 minutes, 6 hours, 1 day (default) or 7 days; the last choice is remembered in the browser.
- No archive is built and no notification email is ever sent; every view counts as a download in "My shares".
- After the chosen duration the link answers `410 Gone` (the expired page for browsers, the same status for embeds)
  and the stored file is purged by the next cleanup run, at most 30 minutes later. A deleted direct link answers 410
  as well. Direct links show a "Direct link" badge in "My shares", can be deleted early, and cannot be re-enabled or
  password protected. They count toward the same size and scratch limits as normal shares.
- Creating a direct link seals the draft. The browser copies the link to the clipboard and opens the "Your direct link"
  page (`/shares/created/{token}`, the same one "Show link" opens from "My shares"), which confirms the copy; the next
  visit to the new-share page starts a fresh draft.
- The other share routes (`/s/{token}/files`, `/download`, `/og-image`, `/api/shares/{token}`) answer 403, 302 or 404
  for a direct link because it allows neither preview nor archive download.

For API clients: `POST /api/shares/direct-link` (signed in, JSON `{draftShareId, uploadId, duration}` with `duration`
one of `30m`, `6h`, `1d`, `7d`, the CSRF token in the `X-CSRF-TOKEN` header, body at most 16 KB) returns
`{url, token, expiresAtUtc}`.

### Share links in general

Custom share tokens are 8 to 64 letters, digits, hyphens or underscores (generated tokens are 8 alphanumeric
characters). The minimum does not make a custom link secret: it bounds guessing together with the per-IP limiters, so
avoid dictionary words when a link should stay private. A share whose owner deleted it answers every public route
(`/s/{token}` and everything below it, `/api/shares/{token}`) with 404, exactly like an unknown token; an expired share
answers 410 (the download page still renders its "expired" view with that status). The anonymous summary at
`/api/shares/{token}` returns only what the download page itself shows, and for a password-protected share nothing but
`requiresPassword` and `expiresAtUtc`.

## Operations

### Health endpoints

| Endpoint | Returns |
| --- | --- |
| `GET /live` | `200` while the process is up (no checks) |
| `GET /ready` | `200` when the database (and, with `Storage__Provider=S3`, the bucket) is reachable, `503` otherwise |

Both are anonymous, not rate limited, set no cookies and do not depend on DataProtection. Point your container
health check and your load balancer at them.

### Logs

Logs always go to the console (stdout). In addition, unless `Agora__Logging__File__Enabled=false`, a daily rolling
file `agora-YYYYMMDD.log` is written to `Agora__Logging__File__Path` and `Agora__Logging__File__RetainedDays` files are
kept. Legacy `Serilog__WriteTo__0__Args__*` settings from before 0.9.18 still take precedence (see the
[settings reference](#legacy-and-pass-through)). What is and is not logged is described under
[What the app logs](#what-the-app-logs).

### Background jobs and retention

Hangfire runs inside the app process with two queues (`default` and `previews`) and two recurring jobs:

| Job | Schedule | What it does |
| --- | --- | --- |
| `cleanup-expired-shares` | every 30 minutes | Deletes the content of shares expired for more than 7 days (the grace period during which the owner can "Re-enable 24h"), and of expired temporary direct links immediately; removes download events older than `Agora__DownloadEventRetentionDays` |
| `cleanup-zombie-uploads` | every 15 minutes | Removes anonymous drafts idle for `Agora__PublicUploads__DraftRetentionHours`, and staged uploads, other drafts, share-creation status files, `tmp/` files and preview `.lock` markers older than `Agora__ZombieUploadRetentionHours` |

On-demand jobs build shares, generate previews (at most two raster decodes and two PDF renders at once, one retry on
infrastructure errors) and send emails. Deleting a share removes its files, archive and previews.

### Hangfire dashboard

`/hangfire` shows queues, recurring jobs, failed jobs and their console output. It requires a signed-in user with the
`admin` role; everyone else gets the sign-in page.

### Run one replica

Lockouts, rate limiters, the scratch budget, preview claim markers and the share-progress hub are process-local, so
run a single instance of the container per database.

### Previews

Preview and thumbnail generation decodes uploaded images and PDFs inside the app process, so it is budgeted
(see [`Agora__Previews__*`](#agora__previews__)). A source over a budget is not decoded at all; the share shows the
"preview unavailable" image for that file instead. Images are decoded with SkiaSharp; only PNG, JPEG, WEBP and BMP
sources get generated previews, decided from the file's magic bytes rather than the extension (GIF, AVIF and other
uploads are served inline but get no generated preview). PNGs are pre-scanned before any decoder sees them (compressed
text chunks, a second colour profile, more than 64 KB of ancillary chunk data or a malformed chunk layout rejects the
file). PDF pages are rasterized with the longer side at 1200 pixels. The link-preview image (`/s/{token}/og-image`) is
rendered once per share, stored next to the previews as `og.png`, served with `Cache-Control: public, max-age=3600` and
purged with the share; password-protected shares get a generic image that shows no title, file name or file count.

### Upgrade notes

Read the notes for every version between yours and the target. Back up the database and `/app/data` first.

**0.9.23 to 0.9.26:** UI fixes only (direct-link control layout, one-line share rows, footer version, cache-busted
stylesheet and script links). No operator action; the cache-busting in 0.9.26 means no proxy or browser cache needs
purging after this or later upgrades.

**0.9.22:** the container runs as the `app` user (UID 1654): `chown -R 1654:1654` existing bind mounts for `/app/data`
before upgrading. Ownership of shares and download-page templates moves to the account id, backfilled once from the
uploader address at the first start (see [Migrations and upgrades](#migrations-and-upgrades)). Confirmation links now
open a page with a confirm button. Custom share tokens need at least 8 characters (generated: 8); custom upload codes
need at least 8 (generated: 12); shorter codes that already exist keep working until changed. New: temporary direct
links, security headers with the report-only CSP (`Agora__SecurityHeaders__Enabled`), PBKDF2 with 600,000 iterations
(hashes are upgraded at sign-in), new passwords must be 8 to 128 characters. Deleted shares answer 404 and expired
ones 410 on every public route; the created page moved to `/shares/created/{token}` (old links redirect).

**0.9.21:** previews are rendered with SkiaSharp instead of ImageSharp. Only PNG, JPEG, WEBP and BMP sources get
generated previews; GIF uploads no longer get one. No configuration change.

**0.9.20:** `Agora__PublicBaseUrl` is required (startup fails without it outside `Development`/`E2E`), and
`X-Forwarded-*` headers are honoured only from loopback and the proxies in `Agora__TrustedProxies`; set it to your
reverse proxy's address or every visitor shares one rate-limit bucket. Cookies are `Secure` in `Production`
(set `Agora__Auth__SecureCookies=SameAsRequest` only for private HTTP-only installs), so the site must be served over
HTTPS. Sign-in cookies now carry a security stamp and cookies issued before this version are rejected: every existing
session is signed out once. Received shares from public upload links now expire (owner's default expiry). Uploaded
files are served by their extension-derived type only, SVG backgrounds are no longer accepted, and the new limits
(`Agora__RateLimits__*`, `Agora__Previews__*`, `Agora__PublicUploads__*`, `Agora__Scratch__*`, `Agora__GeoLookup__*`)
apply with the defaults listed above.

**0.9.19:** object storage (`Storage__Provider=S3`) is available; the default `FileSystem` provider keeps content under
`StorageRoot` exactly as before. Archives are now built in `StorageRoot/tmp` and deleting a share also deletes its
previews (which earlier versions left behind). `/ready` checks the bucket in S3 mode.

**0.9.18:** DataProtection keys are persisted (`DataProtection__KeysPath`, `/app/data/keys` in the container) under
the fixed application name `Agora`. Before, containers kept keys only in memory, so every restart signed everyone out;
upgrading to 0.9.18 signs all users out (and invalidates open confirmation forms) one last time. A missing
`ConnectionStrings__Default` is now a startup error (the SQLite fallback is gone), PostgreSQL is supported
(`Database__Provider=Postgres`), `/live` and `/ready` exist, and logging moved to `Agora__Logging__File__*` (legacy
Serilog keys still honoured). Multipart upload buffering moved from the system temp directory to `<StorageRoot>/tmp/aspnet`.

## Local development and tests

Prerequisites: .NET SDK 10, Node.js 20+, Docker and tmux.

```bash
./run-dev.sh      # start
./stop-dev.sh     # stop; --delete also removes the SQL Server container
```

`run-dev.sh` opens a tmux session `agora-dev` with three panes: a SQL Server 2022 container (`agora-dev-sql`, port
`18033`, database `agora_dev`, `sa` password from `AGORA_DEV_SQL_PASSWORD` or a default), the app under `dotnet watch`
on `http://127.0.0.1:18080` in the `Development` environment, and the Tailwind watcher. The app uses `./storage` as
`StorageRoot`, writes logs to `./logs` and emails to `./emails` (`Email__Provider=filesystem`). In `Development` a
user `dev@example.com` with the `admin` role is created at startup (its random password is printed in the app log once)
and the sign-in page offers a one-click development login.

Other useful commands:

```bash
dotnet build Agora.slnx
dotnet test tests/Agora.Application.Tests/Agora.Application.Tests.csproj   # unit tests (SQLite in-memory); PostgreSQL and MinIO tests use Testcontainers and skip without Docker
scripts/add-migration.sh <Name>                                           # adds an EF Core migration to both provider sets
cd src/Agora.Web && npm run tailwind:build && npm run ts:build             # rebuild CSS and the TypeScript bundles after changes
```

Set `AGORA_REQUIRE_POSTGRES_TESTS=1` or `AGORA_REQUIRE_S3_TESTS=1` to make skipped container tests a failure. An
opt-in smoke test against a real bucket runs with `dotnet test --filter LiveS3` and the `AGORA_S3_LIVE_*` variables
described in `AGENTS.md`.

End-to-end tests (Playwright) live in `tests/e2e`. Each run starts a dedicated database container (SQL Server on
`18091` or PostgreSQL 17 on `18092`), optionally a MinIO container on `18093`, and the app on `18090` in the `E2E`
environment with `Email__Provider=filesystem` and data under `.e2e-data/runs/<id>`:

```bash
cd tests/e2e
npm install
npm run test:sqlserver     # PLAYWRIGHT_E2E_DB=sqlserver PLAYWRIGHT_E2E_STORAGE=filesystem
npm run test:postgres      # PLAYWRIGHT_E2E_DB=postgres
npm run test:postgres-s3   # PLAYWRIGHT_E2E_DB=postgres PLAYWRIGHT_E2E_STORAGE=s3 (MinIO; fails if durable content lands on disk)
npm run test:all           # all three legs
npm run report             # open the HTML report
```

Project conventions for contributors (naming, migrations, storage invariants, design system) are in
[`AGENTS.md`](./AGENTS.md); the system design is described in [`ARCHITECTURE.md`](./ARCHITECTURE.md) and the UI in
[`docs/STYLEGUIDE.md`](./docs/STYLEGUIDE.md).

## Build (ANDO)

`Agora` includes `build.csando` for pipeline-style builds; the publish profile builds the multi-arch image and pushes
`ghcr.io/aduggleby/agora:<version>` and `:latest`.

```bash
ando run --dind
```

Learn more about ANDO: [andobuild.com](https://andobuild.com)
