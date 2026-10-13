#!/usr/bin/env bash
# Adds an EF Core migration to BOTH migration sets (SQL Server and PostgreSQL).
# Usage: scripts/add-migration.sh <Name>
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "Usage: $0 <MigrationName>" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# The design-time factories use placeholder connection strings; `migrations add` never connects.
unset ConnectionStrings__Default

dotnet tool restore >/dev/null
dotnet build src/Agora.Web/Agora.Web.csproj >/dev/null

common=(--project src/Agora.Infrastructure --startup-project src/Agora.Web --no-build)
dotnet ef migrations add "$1" "${common[@]}" --context AgoraDbContext --output-dir Migrations
dotnet ef migrations add "$1" "${common[@]}" --context PostgresAgoraDbContext --output-dir Migrations/Postgres
