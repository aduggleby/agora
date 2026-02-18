# Agora

Agora is an ASP.NET Core 10 file sharing service. Upload one or more files, generate a ZIP archive on disk, and share a URL for recipients to access a branded download page and download the archive. Shares can optionally require a download password and keep the ZIP encrypted at rest.

## Screenshots

| New Share | Download Page | Download Page Editor |
| --- | --- | --- |
| [![New share page](docs/screenshots/new-share-page.png)](docs/screenshots/new-share-page.png) | [![Download page](docs/screenshots/download-page.png)](docs/screenshots/download-page.png) | [![Download page editor](docs/screenshots/landing-page-editor.png)](docs/screenshots/landing-page-editor.png) |

## Features

- Multi-file upload with ZIP archive generation
- Optional per-share download password with encrypted-at-rest ZIP storage
- Share URL with download page before download
- Share-created success screen with one-click link copy
- Previous shares support reopening the Share Ready link screen
- Previous shares Details modal lists archived filenames and sizes
- Share links default to unique 8-character alphanumeric tokens and can be customized (letters, numbers, `-`, `_`)
- Optional `Show previews` mode auto-adapts recipient view: image mosaic for image-only uploads, and file-by-file preview for mixed uploads
- Download page designer supports configurable download card position (corners, edges, centered)
- Account settings include email and password update forms
- Registration requires email confirmation before first login
- Unconfirmed login attempts redirect to a dedicated email confirmation page
- Email and password changes require confirmation before they take effect
- Forgot password and password reset flows are supported
- Share defaults have a dedicated settings page
- New accounts default download page subtitle is set to `by <account email>`
- Signed-in downloads are excluded from download totals
- Expiry options: date-based or indefinite
- Download notifications (`none`, `once`, `every_time`)
- Download notifications are sent only for explicit download submissions, not share-page visits
- Download event metadata: IP, user-agent, timestamp
- Resend-compatible email integration with configurable API base URL
- Auth emails are queued and sent asynchronously via Hangfire
- Daily rolling Serilog file logs with 30-day retention
- Built-in rate limiting for auth, authenticated user traffic, and share downloads
- CSRF protection on unsafe HTTP methods (forms, fetch, and XHR)
- Login brute-force protection with temporary account lockout after repeated failures

## Project Layout

- `src/Agora.Web` - HTTP API and hosted service
- `src/Agora.Application` - contracts, models, utilities
- `src/Agora.Infrastructure` - EF Core persistence and service implementations
- `src/Agora.Domain` - domain entities
- `tests/Agora.Application.Tests` - unit tests
- `tests/e2e` - Playwright end-to-end tests

## Maintainability Architecture

Recent refactors introduced explicit extension points for safer feature growth:

- Public share HTTP surface is grouped under `src/Agora.Web/Endpoints/PublicShareEndpoints.cs`
- Runtime schema compatibility upgrades are isolated in `src/Agora.Web/Startup/SchemaUpgradeRunner.cs`
- Share content storage/path safety is centralized behind `IShareContentStore` (`src/Agora.Application/Abstractions/IShareContentStore.cs`, `src/Agora.Infrastructure/Services/ShareContentStore.cs`)
- Share recipient rendering behavior is strategy-based (`archive`/`gallery`) via `IShareExperienceRenderer` in `src/Agora.Web/Services/ShareExperienceRendering.cs`
- Share mode values are strongly typed through `ShareModes` in `src/Agora.Application/Models/ShareModes.cs`

For future additions, prefer extending these components instead of growing `Program.cs` or `ShareManager` responsibilities.

## Local Development

Requirements:

- .NET SDK 10.0+

Commands:

```bash
dotnet restore Agora.slnx
dotnet build Agora.slnx
dotnet test tests/Agora.Application.Tests/Agora.Application.Tests.csproj
dotnet run --project src/Agora.Web/Agora.Web.csproj --urls http://127.0.0.1:18080
```

Then open `http://127.0.0.1:18080`.

## Development Scripts

Use the provided scripts to run local development with a dedicated SQL Server container and tmux orchestration:

```bash
./run-dev.sh
```

This starts:
- tmux session `agora-dev`
- SQL Server container `agora-dev-sql` on `localhost:18033`
- Agora app on `http://127.0.0.1:18080`

During development, emails are written to the filesystem instead of being sent:
- `emails/`

Logs are written to:
- `logs/` (Serilog rolling files)
- `.dev/agora-web.log` (app runtime output)
- `.dev/tailwind.log` (Tailwind watch output)

Stop everything:

```bash
./stop-dev.sh
```

Stop and delete dev SQL container:

```bash
./stop-dev.sh --delete
```

## End-to-End Tests

Playwright tests run against a dedicated app instance on port `18090` with an isolated SQLite database:

```bash
cd tests/e2e
npm install
npx playwright install --with-deps chromium
npx playwright test
```

The test runner starts the app automatically. Test data is stored in `.e2e-data/`.

## ANDO Build

This repository includes `build.csando`.

Run validation pipeline (restore -> build -> test):

```bash
ando run
```

Authenticate to GHCR first:

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USERNAME" --password-stdin
```

Run publish profile (build/test, publish artifacts, build and push multi-arch image to GHCR):

```bash
ando run -p publish --dind
```

## Container

Build image:

```bash
docker build -t agora:latest .
```

Run container (only env vars + 1 volume required):

```bash
docker run -d \
  --name agora \
  -p 18080:18080 \
  -e Email__Resend__ApiToken="<your_token>" \
  -e Email__Resend__FromDisplayName="<display_name>" \
  -e Email__Resend__FromAddress="no-reply@yourdomain.com" \
  -e Email__Resend__ApiUrl="https://api.resend.com" \
  -e Agora__PublicBaseUrl="https://files.yourdomain.com" \
  -e ConnectionStrings__Default="Data Source=/app/data/uploads/agora.db" \
  -e Serilog__WriteTo__0__Args__path="/app/data/logs/agora-.log" \
  -v agora_data:/app/data \
  agora:latest
```

## Installing on TrueNAS SCALE (YAML)

### 1. Create Dataset/Directories

Create one dataset for all persistent app data, for example:

- `/mnt/YOUR_POOL/apps/agora/data`

Agora will create and use subfolders inside this mount (for example uploads, logs, and other runtime data).
The default uploads path is `/app/data/uploads`.

### 2. Create SQL Server Database + User

Generate a secure password first:

```bash
openssl rand -base64 32
```

Connect to your SQL Server (for example from `sqlcmd`) and run:

```sql
-- Create database
CREATE DATABASE Agora;
GO

-- Create SQL login
CREATE LOGIN agora WITH PASSWORD = 'REPLACE_WITH_STRONG_PASSWORD';
GO

-- Create DB user + grant permissions
USE Agora;
GO

CREATE USER agora FOR LOGIN agora;
GO

ALTER ROLE db_owner ADD MEMBER agora;
GO
```

Example sqlcmd connection:

```bash
sqlcmd -S YOUR_TRUENAS_IP,1433 -U sa -P 'YOUR_SA_PASSWORD' -C
```

### 3. Install via YAML

In TrueNAS:

1. Open `Apps -> Discover Apps`.
2. Click the three-dot menu (`...`) and select `Install via YAML`.
3. Set application name to `agora`.
4. Paste and adjust this YAML:

```yaml
services:
  agora:
    image: ghcr.io/aduggleby/agora:latest
    pull_policy: always
    ports:
      - "18080:18080"
    environment:
      - ConnectionStrings__Default=Server=YOUR_TRUENAS_IP,1433;Database=Agora;User Id=agora;Password=YOUR_AGORA_PASSWORD;TrustServerCertificate=true
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

### 4. Optional Runtime Configuration

These settings are optional and only needed if you want to override defaults:

- `Serilog__WriteTo__0__Args__path` (default: `logs/agora-.log`)
- `Email__Resend__FromDisplayName` (default: empty; uses just address if unset)
- `Agora__PublicBaseUrl` (default: request host, for example `https://files.example.com`)
- If running behind a reverse proxy (Caddy/Nginx), forward `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` headers to avoid CSRF/origin validation issues.
- `Agora__MaxFilesPerShare` (default: `20`)
- `Agora__MaxFileSizeBytes` (default: `262144000` / 250 MB)
- `Agora__MaxTotalUploadBytes` (default: `1073741824` / 1 GB)
- `Agora__DownloadEventRetentionDays` (default: `90`)
- `Agora__ZombieUploadRetentionHours` (default: `24`)

Rate limiting defaults (built in):

- Auth endpoints (`POST /login`, `POST /register`, `POST /login/development`): `10 requests/minute` per source IP
- Authenticated requests (global): `120 requests/minute` per authenticated account
- Download endpoint (`POST /s/{token}/download`): `20 requests/minute` per `(token, source IP)` pair

### 5. Replace Placeholder Values

- `YOUR_TRUENAS_IP`: IP of your TrueNAS host.
- `YOUR_AGORA_PASSWORD`: password used in `CREATE LOGIN`.
- `YOUR_POOL`: your TrueNAS pool name.
- `YOUR_RESEND_API_TOKEN`: Resend (or compatible provider) token.
- `YOUR_FROM_DISPLAY_NAME`: friendly sender name shown in recipient inboxes.
- `YOUR_VERIFIED_FROM_EMAIL`: sender address verified in your provider.

### 6. Verify

After install, open:

- `http://YOUR_TRUENAS_IP:18080/`

To update, edit the app and bump image tag (or keep `latest`).

## Port Assignment

Agora uses reserved range `18000-18099`.
Default HTTP port: `18080`.
