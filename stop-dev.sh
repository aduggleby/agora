#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_NAME="agora-dev"
SQL_CONTAINER_NAME="agora-dev-sql"
APP_DIR="$ROOT_DIR/src/Agora.Web"
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

if [[ "$DELETE_CONTAINERS" == "true" ]]; then
  if docker ps -a --format '{{.Names}}' | grep -q "^${SQL_CONTAINER_NAME}$"; then
    echo "Deleting SQL Server container ${SQL_CONTAINER_NAME}..."
    docker rm "$SQL_CONTAINER_NAME" >/dev/null
  fi
  echo "Container deletion complete."
fi

echo "Development environment stopped."
echo "Logs:   ${APP_DIR}/logs"
echo "Emails: ${APP_DIR}/emails"
