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
docker run -d \
  --name "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" \
  -e ACCEPT_EULA=Y \
  -e SA_PASSWORD="${PLAYWRIGHT_E2E_SQL_PASSWORD}" \
  -p "${PLAYWRIGHT_E2E_SQL_PORT}:1433" \
  mcr.microsoft.com/mssql/server:2022-latest >/dev/null

ready=0
for _ in $(seq 1 90); do
  if docker logs "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" 2>&1 | rg -q "SQL Server is now ready for client connections"; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "${ready}" -ne 1 ]]; then
  echo "SQL Server container did not become ready in time: ${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" >&2
  docker logs "${PLAYWRIGHT_E2E_SQL_CONTAINER_NAME}" 2>&1 | tail -n 200 >&2 || true
  exit 1
fi

mkdir -p "${PLAYWRIGHT_E2E_DATA_ROOT}/storage" "${PLAYWRIGHT_E2E_DATA_ROOT}/emails" "${PLAYWRIGHT_E2E_DATA_ROOT}/logs"
dotnet run --project src/Agora.Web/Agora.Web.csproj --urls http://127.0.0.1:18090
