#!/bin/sh
set -eu
image=${1:?Usage: smoke-test.sh IMAGE}
container="telegram-mcp-smoke-$$"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$container" --network none \
  --read-only --tmpfs /tmp:size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -e MCP_PUBLIC_HOST=mcp.example.com \
  -e CF_ACCESS_ISSUER=https://example.cloudflareaccess.com \
  -e CF_ACCESS_AUDIENCE=test-audience \
  -e CF_ACCESS_ALLOWED_EMAIL=owner@example.com \
  -e TELEGRAM_BOT_TOKEN=123:test \
  -e 'TELEGRAM_RECIPIENTS={"Alice":"100001"}' \
  -e TELEGRAM_SEND_ENABLED=false \
  "$image" >/dev/null

attempt=0
until docker exec "$container" curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    docker logs "$container"
    exit 1
  fi
  sleep 1
done
status=$(docker exec "$container" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/mcp)
[ "$status" = 401 ]
printf 'Health check passed; unauthenticated MCP returns %s.\n' "$status"
