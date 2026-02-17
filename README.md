# Agora

Agora is an ASP.NET Core 10 file sharing service. Upload one or more files, generate a ZIP archive on disk, and share a URL for recipients to access a branded landing page and download the archive.

## Features

- Multi-file upload with ZIP archive generation
- Share URL with landing page before download
- Expiry options: date-based or indefinite
- Download notifications (`none`, `once`, `every_time`)
- Download event metadata: IP, user-agent, timestamp
- Resend-compatible email integration with configurable API base URL
- Daily rolling Serilog file logs with 30-day retention

## Project Layout

- `src/Agora.Web` - HTTP API and hosted service
- `src/Agora.Application` - contracts, models, utilities
- `src/Agora.Infrastructure` - EF Core persistence and service implementations
- `src/Agora.Domain` - domain entities
- `tests/Agora.Application.Tests` - unit tests

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
- `src/Agora.Web/emails`

Logs are written to:
- `src/Agora.Web/logs`

Stop everything:

```bash
./stop-dev.sh
```

Stop and delete dev SQL container:

```bash
./stop-dev.sh --delete
```

## ANDO Build

This repository includes `build.csando`.

Run validation pipeline (restore -> build -> test):

```bash
ando run
```

Run publish + container build profile:

```bash
ando run -p publish
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
  -e Email__Resend__FromAddress="no-reply@yourdomain.com" \
  -e Email__Resend__ApiUrl="https://api.resend.com" \
  -e ConnectionStrings__Default="Data Source=/app/data/uploads/agora.db" \
  -e Agora__StorageRoot="/app/data/uploads" \
  -e Serilog__WriteTo__0__Args__path="/app/data/logs/agora-.log" \
  -v agora_data:/app/data \
  agora:latest
```

## Installing on TrueNAS SCALE (Container)

Tested workflow for custom Docker app deployment:

1. Build and push your image to a registry accessible by TrueNAS (Docker Hub/GHCR/private registry).
2. In TrueNAS, open **Apps** and create a custom app (Docker image).
3. Set image to your Agora image tag.
4. Set container port to `18080` and map host port to `18080` (or another free host port).
5. Add environment variables:
   - `Email__Resend__ApiToken`
   - `Email__Resend__FromAddress`
   - `Email__Resend__ApiUrl`
   - `ConnectionStrings__Default=Data Source=/app/data/uploads/agora.db`
   - `Agora__StorageRoot=/app/data/uploads`
   - `Serilog__WriteTo__0__Args__path=/app/data/logs/agora-.log`
6. Add persistent host path/dataset:
   - `/app/data` -> single dataset containing uploads/database and rolling logs
7. Deploy app.
8. Verify app health by opening `http://<truenas-host>:18080/`.

Recommended TrueNAS datasets:

- `tank/apps/agora/data`

## Runtime Configuration

Important settings:

- `ConnectionStrings__Default`
- `Agora__StorageRoot`
- `Serilog__WriteTo__0__Args__path`
- `Agora__MaxFilesPerShare`
- `Agora__MaxFileSizeBytes`
- `Agora__MaxTotalUploadBytes`
- `Email__Resend__ApiToken`
- `Email__Resend__ApiUrl`
- `Email__Resend__FromAddress`

## Port Assignment

Agora uses reserved range `18000-18099`.
Default HTTP port: `18080`.
