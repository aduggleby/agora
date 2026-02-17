#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_NAME="agora-dev"
SQL_CONTAINER_NAME="agora-dev-sql"
LOG_DIR="$ROOT_DIR/logs"
EMAIL_DIR="$ROOT_DIR/emails"
APP_PORT="18080"
SQL_PORT="18033"
DELETE_CONTAINERS="false"

for arg in "$@"; do
  case "$arg" in
    --delete|-d)
      DELETE_CONTAINERS="true"
      ;;
    *)
      echo "Unknown argument: $arg"
      echo "Usage: ./stop-dev.sh [--delete|-d]"
      exit 1
      ;;
  esac
done

kill_port_listeners() {
  local port="$1"
  local pids
  pids="$(ss -ltnp "( sport = :${port} )" 2>/dev/null | rg -o 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)"
  if [[ -z "$pids" ]]; then
    return
  fi

  echo "Stopping processes bound to port ${port}: ${pids}"
  for pid in $pids; do
    kill "$pid" 2>/dev/null || true
  done

  sleep 1

  local remaining
  remaining="$(ss -ltnp "( sport = :${port} )" 2>/dev/null | rg -o 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)"
  if [[ -n "$remaining" ]]; then
    echo "Force-killing remaining processes on port ${port}: ${remaining}"
    for pid in $remaining; do
      kill -9 "$pid" 2>/dev/null || true
    done
  fi
}

kill_orphaned_agora_processes() {
  local patterns=(
    "dotnet watch --project .*src/Agora.Web/Agora.Web.csproj run"
    "dotnet run --project src/Agora.Web/Agora.Web.csproj"
    "dotnet run --urls http://localhost:${APP_PORT}"
    "src/Agora.Web/bin/Debug/net10.0/Agora.Web --urls http://localhost:${APP_PORT}"
  )

  for pattern in "${patterns[@]}"; do
    pkill -f "$pattern" 2>/dev/null || true
  done
}

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "Stopping tmux session ${SESSION_NAME}..."
  tmux kill-session -t "$SESSION_NAME"
else
  echo "tmux session ${SESSION_NAME} is not running."
fi

if docker ps --format '{{.Names}}' | grep -q "^${SQL_CONTAINER_NAME}$"; then
  echo "Stopping SQL Server container ${SQL_CONTAINER_NAME}..."
  docker stop "$SQL_CONTAINER_NAME" >/dev/null
else
  echo "SQL Server container ${SQL_CONTAINER_NAME} is not running."
fi

kill_port_listeners "$APP_PORT"
kill_port_listeners "$SQL_PORT"
kill_orphaned_agora_processes

sleep 1
kill_port_listeners "$APP_PORT"
kill_port_listeners "$SQL_PORT"

if [[ "$DELETE_CONTAINERS" == "true" ]]; then
  if docker ps -a --format '{{.Names}}' | grep -q "^${SQL_CONTAINER_NAME}$"; then
    echo "Deleting SQL Server container ${SQL_CONTAINER_NAME}..."
    docker rm "$SQL_CONTAINER_NAME" >/dev/null
  fi
  echo "Container deletion complete."
fi

echo "Development environment stopped."
echo "Logs:   ${LOG_DIR}"
echo "Emails: ${EMAIL_DIR}"
