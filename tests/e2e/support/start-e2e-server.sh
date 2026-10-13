#!/usr/bin/env bash
set -euo pipefail

: "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME:?PLAYWRIGHT_E2E_SQL_CONTAINER_NAME is required}"
: "${PLAYWRIGHT_E2E_SQL_PORT:?PLAYWRIGHT_E2E_SQL_PORT is required}"
: "${PLAYWRIGHT_E2E_SQL_PASSWORD:?PLAYWRIGHT_E2E_SQL_PASSWORD is required}"
: "${PLAYWRIGHT_E2E_DATA_ROOT:?PLAYWRIGHT_E2E_DATA_ROOT is required}"

docker rm -f "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" >/dev/null 2>&1 || true
existing_container_id="$(docker ps --filter "publish=${PLAYWRIGHT_E2E_SQL_PORT}" --format '{{.ID}}' | head -n 1 || true)"
if [[ -n "${existing_container_id}" ]]; then
  docker rm -f "${existing_container_id}" >/dev/null 2>&1 || true
fi
if [[ "${PLAYWRIGHT_E2E_DB:-sqlserver}" == "postgres" ]]; then
  docker run -d \
    --name "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" \
    -e POSTGRES_PASSWORD="${PLAYWRIGHT_E2E_SQL_PASSWORD}" \
    -e POSTGRES_DB=agora_e2e \
    -p "${PLAYWRIGHT_E2E_SQL_PORT}:5432" \
    postgres:17 >/dev/null
  ready_check() {
    # TCP check: the image's init server listens on the unix socket only, so this waits for the real server.
    docker exec "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" pg_isready -h 127.0.0.1 -U postgres -d agora_e2e >/dev/null 2>&1
  }
else
  docker run -d \
    --name "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" \
    -e ACCEPT_EULA=Y \
    -e SA_PASSWORD="${PLAYWRIGHT_E2E_SQL_PASSWORD}" \
    -p "${PLAYWRIGHT_E2E_SQL_PORT}:1433" \
    mcr.microsoft.com/mssql/server:2022-latest >/dev/null
  ready_check() {
    docker logs "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" 2>&1 | rg -q "SQL Server is now ready for client connections"
  }
fi

ready=0
for _ in $(seq 1 90); do
  if ready_check; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "${ready}" -ne 1 ]]; then
  echo "Database container did not become ready in time: ${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" >&2
  docker logs "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" 2>&1 | tail -n 200 >&2 || true
  exit 1
fi

mkdir -p "${PLAYWRIGHT_E2E_DATA_ROOT}/storage" "${PLAYWRIGHT_E2E_DATA_ROOT}/emails" "${PLAYWRIGHT_E2E_DATA_ROOT}/logs"
dotnet run --no-launch-profile --project src/Agora.Web/Agora.Web.csproj --urls http://127.0.0.1:18090
