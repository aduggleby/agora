# Deployment

This document covers container deployment for Agora, including Docker and TrueNAS SCALE.

## Container Contract

Production/container deployments should use:

- Environment variables for configuration
- One writable volume mounted at `/app/data`
- Default HTTP port `18080`

All mutable runtime data should remain under `/app/data` (uploads, database, logs).

## Docker

### Build Image

```bash
docker build -t agora:latest .
```

### Run Container

```bash
docker run -d \
  --name agora \
  -p 18080:18080 \
  -e ConnectionStrings__Default="Data Source=/app/data/uploads/agora.db" \
  -e Agora__PublicBaseUrl="https://files.yourdomain.com" \
  -e Email__Provider="Resend" \
  -e Email__Resend__ApiToken="<your_token>" \
  -e Email__Resend__FromDisplayName="<display_name>" \
  -e Email__Resend__FromAddress="no-reply@yourdomain.com" \
  -e Email__Resend__ApiUrl="https://api.resend.com" \
  -e Serilog__WriteTo__0__Args__path="/app/data/logs/agora-.log" \
  -v agora_data:/app/data \
  agora:latest
```

## Runtime Environment Variables

### Core

| Variable | Default | Notes |
| --- | --- | --- |
| `ConnectionStrings__Default` | `Data Source=/app/data/uploads/agora.db` | SQLite by default |
| `Agora__PublicBaseUrl` | request host | Recommended in production |
| `Serilog__WriteTo__0__Args__path` | `/app/data/logs/agora-.log` | Daily rolling logs, 30-day retention |

### Upload and Retention

| Variable | Default |
| --- | --- |
| `Agora__MaxFilesPerShare` | `20` |
| `Agora__MaxFileSizeBytes` | `5368709120` (5 GB) |
| `Agora__MaxTotalUploadBytes` | `10737418240` (10 GB) |
| `Agora__DownloadEventRetentionDays` | `90` |
| `Agora__ZombieUploadRetentionHours` | `24` |

### Email

| Variable | Default | Notes |
| --- | --- | --- |
| `Email__Provider` | `Resend` | Email provider mode |
| `Email__Resend__ApiToken` | none | Required for delivery |
| `Email__Resend__FromDisplayName` | empty | Optional |
| `Email__Resend__FromAddress` | none | Must be verified |
| `Email__Resend__ApiUrl` | `https://api.resend.com` | Override for compatible providers |

## Reverse Proxy Notes

If running behind Caddy/Nginx/Traefik, forward these headers:

- `X-Forwarded-For`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`

Without these, CSRF/origin checks and absolute URL generation may fail.

## TrueNAS SCALE (Install via YAML)

### 1. Create Dataset

Create one dataset for app data, for example:

- `/mnt/YOUR_POOL/apps/agora/data`

### 2. Install App

In TrueNAS:

1. Open `Apps -> Discover Apps`.
2. Click `...` and select `Install via YAML`.
3. Set app name to `agora`.
4. Paste and adjust:

```yaml
services:
  agora:
    image: ghcr.io/aduggleby/agora:latest
    pull_policy: always
    ports:
      - "18080:18080"
    environment:
      - ConnectionStrings__Default=Data Source=/app/data/uploads/agora.db
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

### 3. Replace Placeholders

- `YOUR_POOL`: your TrueNAS pool
- `YOUR_RESEND_API_TOKEN`: provider token
- `YOUR_FROM_DISPLAY_NAME`: sender display name
- `YOUR_VERIFIED_FROM_EMAIL`: verified sender address

### 4. Verify

Open:

- `http://YOUR_TRUENAS_IP:18080/`

For updates, edit the app and change image tag (or continue using `latest`).

## Optional: SQL Server Instead of SQLite

You can replace SQLite with SQL Server by setting `ConnectionStrings__Default`, for example:

```text
Server=YOUR_TRUENAS_IP,1433;Database=Agora;User Id=agora;Password=YOUR_AGORA_PASSWORD;TrustServerCertificate=true
```
