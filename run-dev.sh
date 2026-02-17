#!/usr/bin/env bash
set -euo pipefail

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required. Please install tmux and retry."
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required for Tailwind CSS watch mode. Please install Node.js and retry."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV_DIR="$ROOT_DIR/.dev"
SESSION_NAME="agora-dev"
APP_DIR="$ROOT_DIR/src/Agora.Web"
APP_LOG_DIR="$APP_DIR/logs"
APP_EMAIL_DIR="$APP_DIR/emails"
TAILWIND_INPUT="$APP_DIR/Styles/tailwind.css"
TAILWIND_OUTPUT="$APP_DIR/wwwroot/css/site.css"
TAILWIND_LOG_FILE="$DEV_DIR/tailwind.log"

mkdir -p "$DEV_DIR" "$ROOT_DIR/storage" "$APP_LOG_DIR" "$APP_EMAIL_DIR" "$(dirname "$TAILWIND_OUTPUT")"

SQL_CONTAINER_NAME="agora-dev-sql"
SQL_IMAGE="mcr.microsoft.com/mssql/server:2022-latest"
SQL_PORT="18033"
APP_PORT="18080"
SQL_DB_NAME="agora_dev"
SQL_SA_PASSWORD="${AGORA_DEV_SQL_PASSWORD:-AgoraDev!Passw0rd}"
APP_LOG_FILE="$DEV_DIR/agora-web.log"
SERILOG_PATH="$APP_LOG_DIR/agora-.log"

ENV_FILE="$DEV_DIR/dev.env"
cat > "$ENV_FILE" <<ENV_EOF
ROOT_DIR="$ROOT_DIR"
SQL_CONTAINER_NAME="$SQL_CONTAINER_NAME"
SQL_IMAGE="$SQL_IMAGE"
SQL_PORT="$SQL_PORT"
SQL_DB_NAME="$SQL_DB_NAME"
SQL_SA_PASSWORD="$SQL_SA_PASSWORD"
APP_PORT="$APP_PORT"
APP_LOG_FILE="$APP_LOG_FILE"
APP_EMAIL_DIR="$APP_EMAIL_DIR"
SERILOG_PATH="$SERILOG_PATH"
TAILWIND_INPUT="$TAILWIND_INPUT"
TAILWIND_OUTPUT="$TAILWIND_OUTPUT"
TAILWIND_LOG_FILE="$TAILWIND_LOG_FILE"
ENV_EOF

if [[ ! -f "$APP_DIR/package.json" ]]; then
  echo "Missing $APP_DIR/package.json. Add Tailwind tooling config and retry."
  exit 1
fi

if [[ ! -f "$TAILWIND_INPUT" ]]; then
  echo "Missing Tailwind input CSS: $TAILWIND_INPUT"
  exit 1
fi

if [[ ! -d "$APP_DIR/node_modules" ]]; then
  echo "Installing frontend dependencies in $APP_DIR..."
  npm install --prefix "$APP_DIR"
fi

SQL_SCRIPT="$DEV_DIR/tmux-sql.sh"
cat > "$SQL_SCRIPT" <<'SQL_EOF'
#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev.env"

echo "[sql] Ensuring SQL Server container exists..."
if ! docker ps -a --format '{{.Names}}' | grep -q "^${SQL_CONTAINER_NAME}$"; then
  docker run -d \
    --name "$SQL_CONTAINER_NAME" \
    -e ACCEPT_EULA=Y \
    -e MSSQL_PID=Developer \
    -e MSSQL_SA_PASSWORD="$SQL_SA_PASSWORD" \
    -p "$SQL_PORT":1433 \
    "$SQL_IMAGE" >/dev/null
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${SQL_CONTAINER_NAME}$"; then
  docker start "$SQL_CONTAINER_NAME" >/dev/null
fi

echo "[sql] Waiting for SQL Server readiness..."
for i in {1..120}; do
  if docker exec "$SQL_CONTAINER_NAME" /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$SQL_SA_PASSWORD" -Q "SELECT 1" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [[ "$i" == "120" ]]; then
    echo "[sql] SQL Server did not become ready in time."
    exit 1
  fi
done

docker exec "$SQL_CONTAINER_NAME" /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$SQL_SA_PASSWORD" -Q "IF DB_ID('${SQL_DB_NAME}') IS NULL CREATE DATABASE [${SQL_DB_NAME}]" >/dev/null

echo "[sql] Ready: ${SQL_CONTAINER_NAME} on localhost:${SQL_PORT}, DB=${SQL_DB_NAME}"
while true; do sleep 3600; done
SQL_EOF
chmod +x "$SQL_SCRIPT"

APP_SCRIPT="$DEV_DIR/tmux-app.sh"
cat > "$APP_SCRIPT" <<'APP_EOF'
#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev.env"

CONNECTION_STRING="Server=127.0.0.1,${SQL_PORT};Database=${SQL_DB_NAME};User Id=sa;Password=${SQL_SA_PASSWORD};Encrypt=True;TrustServerCertificate=True"

echo "[app] Waiting for SQL Server readiness..."
for i in {1..120}; do
  if docker exec "$SQL_CONTAINER_NAME" /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$SQL_SA_PASSWORD" -Q "SELECT 1" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [[ "$i" == "120" ]]; then
    echo "[app] SQL Server did not become ready in time."
    exit 1
  fi
done

echo "[app] Starting Agora on http://127.0.0.1:${APP_PORT}"
cd "$ROOT_DIR"
ASPNETCORE_ENVIRONMENT=Development \
ASPNETCORE_URLS="http://127.0.0.1:${APP_PORT}" \
ConnectionStrings__Default="$CONNECTION_STRING" \
Email__Provider=filesystem \
Email__FileSystem__OutputDirectory="$APP_EMAIL_DIR" \
Serilog__WriteTo__0__Args__path="$SERILOG_PATH" \
dotnet watch --project src/Agora.Web/Agora.Web.csproj run --no-launch-profile 2>&1 | tee -a "$APP_LOG_FILE"
APP_EOF
chmod +x "$APP_SCRIPT"

TAILWIND_SCRIPT="$DEV_DIR/tmux-tailwind.sh"
cat > "$TAILWIND_SCRIPT" <<'TAILWIND_EOF'
#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev.env"

echo "[tailwind] Building and watching ${TAILWIND_INPUT}"
cd "$ROOT_DIR/src/Agora.Web"
npx @tailwindcss/cli -i "$TAILWIND_INPUT" -o "$TAILWIND_OUTPUT" --watch 2>&1 | tee -a "$TAILWIND_LOG_FILE"
TAILWIND_EOF
chmod +x "$TAILWIND_SCRIPT"

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "tmux session '${SESSION_NAME}' is already running."
else
  tmux new-session -d -s "$SESSION_NAME" -n servers "bash '$SQL_SCRIPT'"
  tmux split-window -h -t "$SESSION_NAME:servers" "bash '$APP_SCRIPT'"
  tmux split-window -v -t "$SESSION_NAME:servers.1" "bash '$TAILWIND_SCRIPT'"
  tmux select-layout -t "$SESSION_NAME:servers" tiled
fi

echo "Waiting for Agora app to be ready..."
for i in {1..150}; do
  if curl -fsS "http://127.0.0.1:${APP_PORT}/" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [[ "$i" == "150" ]]; then
    echo "Agora app did not become ready in time."
    echo "Check tmux session: tmux attach -t ${SESSION_NAME}"
    exit 1
  fi
done

echo ""
echo "Agora development environment is running in tmux session '${SESSION_NAME}':"
echo "- App URL:            http://127.0.0.1:${APP_PORT}"
echo "- SQL Server:         localhost:${SQL_PORT} (container: ${SQL_CONTAINER_NAME})"
echo "- SQL Database:       ${SQL_DB_NAME}"
echo "- App log file:       ${APP_LOG_FILE}"
echo "- Tailwind log file:  ${TAILWIND_LOG_FILE}"
echo "- Serilog log folder: ${APP_LOG_DIR}"
echo "- Email dump folder:  ${APP_EMAIL_DIR}"
echo ""
echo "Attaching to tmux session '${SESSION_NAME}' (split panes: SQL | app watch | tailwind watch)..."

if [[ -n "${TMUX:-}" ]]; then
  tmux switch-client -t "${SESSION_NAME}:servers"
else
  exec tmux attach -t "${SESSION_NAME}:servers"
fi
