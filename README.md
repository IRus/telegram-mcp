# Telegram MCP

Send ChatGPT file attachments to named Telegram recipients through an MCP server.
The service is written in Kotlin/Native and runs behind Cloudflare Access Managed OAuth.

The single tool, `send_to_telegram`, accepts an attachment, an optional caption,
and an explicit recipient name. A successful call returns the Telegram message ID.
It does not read chat history or act as a general Telegram client.

## Container image

The public image is `ghcr.io/irus/telegram-mcp:main`, currently for **Linux ARM64**.
Each successful main-branch build also publishes `sha-<full-commit-sha>`.
Pin a digest for deployments that should not follow a moving tag.

```sh
docker pull ghcr.io/irus/telegram-mcp:main
cp .env.example .env
mkdir -p secrets
# Save the Telegram bot token in secrets/bot-token, readable by UID 1000.
# On a Linux Docker host: chown 1000:1000 secrets/bot-token && chmod 600 secrets/bot-token
# Replace the example configuration before starting.
docker compose -f compose.example.yaml up -d
curl -fsS http://127.0.0.1:8080/health
```

The example binds only to localhost. Place the service behind Cloudflare Tunnel
and Access before connecting an external MCP client. If cloudflared runs in a
container, connect both containers to a shared network and route to
`http://telegram_mcp:8080`; its localhost is not the Docker host's localhost.
The MCP endpoint is `/mcp`. The unauthenticated origin endpoint returns 401;
only `/health` is public. There is no development authentication bypass.

## Configuration

The following are the environment variables consumed by the executable.

| Variable | Purpose |
| --- | --- |
| `MCP_PUBLIC_HOST` | Public hostname, for example `mcp.example.com` |
| `CF_ACCESS_ISSUER` | `https://<team>.cloudflareaccess.com` |
| `CF_ACCESS_AUDIENCE` | Access application's audience tag |
| `CF_ACCESS_ALLOWED_EMAIL` | Comma-separated allowed login emails; singular name retained for compatibility |
| `TELEGRAM_BOT_TOKEN_FILE` | Path to the bot token file; preferred over `TELEGRAM_BOT_TOKEN` |
| `TELEGRAM_BOT_TOKEN` | Alternative token source when no token file is configured |
| `TELEGRAM_RECIPIENTS` | JSON mapping explicit names to positive private Telegram chat IDs |
| `TELEGRAM_SEND_ENABLED` | Sending is disabled unless the value is exactly `true` |
| `FILE_DOWNLOAD_HOSTS` | Comma-separated exact HTTPS hostnames or `*.domain` patterns; default `files.oaiusercontent.com` |
| `MAX_FILE_BYTES` | Download limit in bytes; default 20 MiB, maximum 50 MiB |

Example recipient configuration (fictional IDs):

```dotenv
TELEGRAM_RECIPIENTS='{"Alice":"100001","Bob":"100002"}'
```

Recipients must start the Telegram bot before it can send to their private chats.
Names are case-sensitive; there is no default recipient. `me`, raw numeric IDs,
and unknown names are rejected before any network request. All allowed logins
share access to the configured recipients; this is not a per-user address book.
Refresh the client's tool schema after changing the recipient mapping.

The image runs as UID/GID 1000. Token files must be readable by that UID.
To rotate a token, replace the file and recreate the service. Keep token files
and `.env` out of version control.

## Cloudflare Access

1. Create a self-hosted Access application covering the service's public hostname.
2. Add an Allow policy for the intended users. Configure the same emails in
   `CF_ACCESS_ALLOWED_EMAIL`.
3. Enable Managed OAuth and dynamic client registration. Allow the redirect URI
   shown by your MCP client; avoid broad redirect allowlists.
4. Set the issuer, audience, and public hostname in the server configuration.
5. Route the hostname through a Cloudflare Tunnel to the server on port 8080.
6. Keep sending disabled while verifying OAuth and MCP tool discovery. Enable
   it only when ready to send files.

Cloudflare handles OAuth and forwards the identity assertion in
`Cf-Access-Jwt-Assertion`. This service verifies its RS256 signature against the
configured issuer, as well as issuer, audience, expiry, token type, subject,
and allowed email. Ordinary browser cookie login alone is not the intended MCP
client authentication flow. See [Cloudflare Managed OAuth documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/).

## File transfers and retries

The attachment object requires `file_id` and `download_url`; `file_name` and
`mime_type` are optional. The descriptor includes `openai/fileParams` so the
client can supply a temporary download URL. A bare file ID or `sandbox:/mnt/data`
path is not a downloadable attachment. Do not invent a URL.

Downloads require HTTPS on port 443, no credentials or fragment, and a host
matching the configured allowlist. Redirects are rejected. Wildcards match
subdomains on a dot boundary, not the bare domain or lookalike suffixes.
Allow only storage hosts you trust: a wildcard can include storage belonging to
other accounts. One file is buffered and sent at a time, within the byte limit.

Telegram sends are never automatically retried. A network error may happen
after Telegram has accepted the document; repeating the tool call can create a
duplicate. Check the chat before retrying an uncertain delivery.

Rejected requests report fixed error codes such as `DOWNLOAD_URL_MISSING`,
`DOWNLOAD_URL_NOT_HTTPS`, and `DOWNLOAD_HOST_NOT_ALLOWED`. Rejected-host logs
include the hostname, not the signed URL, file ID, token, or contents.

## Development

The wrapper pins Kotlin Toolchain 0.12.2. Modules are `core`, `server-linux`, and
`server-macos`; development/testing supports macOS ARM64 and Linux ARM64.

```sh
# On macOS ARM64:
./kotlin test -m core -p macosArm64

# On Linux ARM64:
./kotlin test -m core -p linuxArm64

# Produce an optimized Linux ARM64 executable in dist/:
./build-image.sh

# On a Linux ARM64 Docker host:
docker build -t telegram-mcp:local .
./scripts/smoke-test.sh telegram-mcp:local
```

CI runs the Linux ARM64 tests, builds the executable and image, then checks
health and unauthenticated MCP rejection without network access. Only a
successful main-branch build publishes to GHCR, using `GITHUB_TOKEN`.
The published image is the same image that passed the container smoke test.
The tests use mock transports and do not send real Telegram messages.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
