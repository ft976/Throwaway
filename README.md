# Throwaway — Disposable Temporary Email Service

A production-ready, receive-only disposable email application built with Node.js 20, Express 4, `smtp-server`, `mailparser`, `sanitize-html`, Redis 7, and a vanilla HTML/CSS/JS frontend.

## Quick Start (Docker Compose)

1. Copy `.env.example` to `.env` and set your domains:

```bash
cp .env.example .env
```

Edit `.env`:

```env
WEB_DOMAIN=ft97.com
DOMAINS=ft97.com
```

2. Start all services (`app`, `redis`, and `caddy`):

```bash
docker compose up -d --build
```

3. Verify the health endpoint:

```bash
curl -fsS https://ft97.com/healthz
# ok
```

## DNS Records (`ft97.com`)

Configure the following DNS records for your domain (`ft97.com`):

| Type | Host / Name | Value / Target | Priority | Purpose |
|---|---|---|---|---|
| `A` | `@` (or `web`) | `<YOUR_SERVER_PUBLIC_IP>` | — | Routes web traffic (`https://ft97.com`) to Caddy |
| `A` | `mx` | `<YOUR_SERVER_PUBLIC_IP>` | — | Mail exchanger hostname (`mx.ft97.com`) |
| `MX` | `@` | `mx.ft97.com` | `10` | Directs incoming mail for `*@ft97.com` to your SMTP server |
| `TXT` | `@` | `v=spf1 -all` | — | Strict SPF policy declaring this domain never sends outbound mail |

> **Important Note on Current `ft97.com` DNS:** Before switching DNS, replace any parked Null MX (`0 .`) record on `ft97.com` with `MX 10 mx.ft97.com` (for direct SMTP port 25) or configure Cloudflare Email Routing using `/cloudflare-worker/email-worker.js` pointing to `POST https://ft97.com/api/v1/inbound/email`.

If you list additional domains in `DOMAINS` (for example `altdomain.com`), add an `MX` record (`10 mx.ft97.com`) and `TXT` SPF record (`v=spf1 -all`) on each additional mail domain.

## Firewall & Port 25 Notice

Open the following inbound TCP ports on your server firewall / security group:

- **Port 25** (`SMTP`) — inbound email delivery (mapped to container port `2525`)
- **Port 80** (`HTTP`) — ACME HTTP-01 challenge and automatic HTTPS redirect
- **Port 443** (`HTTPS`) — web UI and REST API via Caddy

> **Important:** Many cloud providers (AWS EC2, GCP, DigitalOcean, Azure, Hetzner, Vultr) block inbound or outbound **port 25** by default on new accounts. Check your provider's networking rules and request port 25 unblocking if external mail servers cannot connect to `mx.ft97.com:25`.

## Optional STARTTLS Setup for SMTP

Caddy handles HTTPS certificates automatically for ports 80/443. To also offer `STARTTLS` on the SMTP server (port 25) without requiring TLS from senders:

1. Obtain a certificate for `mx.yourdomain.com` using Certbot (make sure port 80 is free temporarily or use DNS-01):

```bash
sudo certbot certonly --standalone -d mx.yourdomain.com
```

2. Mount `/etc/letsencrypt/live/mx.yourdomain.com/` read-only into the `app` container in `docker-compose.yml` and set in `.env`:

```env
TLS_KEY_PATH=/certs/privkey.pem
TLS_CERT_PATH=/certs/fullchain.pem
```

When unset, the SMTP server accepts plaintext delivery cleanly (`STARTTLS` disabled).

## Local Development & Running Tests

Install dependencies:

```bash
npm install
```

Run the unit and integration test suite (`vitest` + `nodemailer`):

```bash
npm test
```

Run ESLint and syntax checks:

```bash
npm run lint
npm run build
```

Run locally in development mode (uses in-memory fallback when `REDIS_URL` is not provided, or connects to local Redis when `REDIS_URL` is set):

```bash
npm run dev
```

For production outside Docker, provide `.env` with `DOMAINS` and `REDIS_URL` and run:

```bash
npm start
```

## Public API (`/api/v1`) & OpenAPI

All JSON endpoints are served under `/api/v1/*` (and aliased at `/api/*`) with `Cache-Control: no-store`.
The machine-readable OpenAPI 3.0.3 schema is available at:

```text
GET /api/v1/openapi.json
```

| Method & Path | Auth / Secret | Purpose |
|---|---|---|
| `GET /api/v1/health` | None | JSON Redis + API health check |
| `GET /api/v1/domains` | None | List configured receiving domains |
| `GET /api/v1/meta` | None | Service TTL, limits, and webhook capability status |
| `GET /api/v1/openapi.json` | None | OpenAPI 3.0.3 specification |
| `POST /api/v1/inbox` | Optional `X-API-Key` | Create a random or custom inbox (`{ username?, domain? }`); returns one-time `token` |
| `GET /api/v1/inbox/:address` | `Authorization: Bearer <token>` | List messages (supports `ETag` / `If-None-Match` -> `304`) |
| `GET /api/v1/inbox/:address/stream` | `Authorization: Bearer <token>` | Real-time Server-Sent Events (`connected`, `message`, `deleted`) |
| `POST /api/v1/inbox/:address/extend` | `Authorization: Bearer <token>` | Reset inbox TTL across all Redis keys |
| `POST /api/v1/inbox/:address/rotate-token` | `Authorization: Bearer <token>` | Issue a new inbox Bearer token and invalidate the old one |
| `DELETE /api/v1/inbox/:address` | `Authorization: Bearer <token>` | Immediately delete inbox and all messages |
| `GET /api/v1/inbox/:address/messages/:id` | `Authorization: Bearer <token>` | Read sanitized HTML + plain text + attachment metadata, marks `read` |
| `DELETE /api/v1/inbox/:address/messages/:id` | `Authorization: Bearer <token>` | Delete a single message |
| `POST /api/v1/keys` | None | Issue a scoped `tw_live_...` developer API key (higher rate limits) |
| `GET /api/v1/keys/me` | `X-API-Key: tw_live_...` | Inspect developer API key metadata and expiration |
| `DELETE /api/v1/keys/me` | `X-API-Key: tw_live_...` | Revoke the caller's developer API key |
| `POST /api/v1/inbound/email` | `X-Webhook-Secret: <INBOUND_WEBHOOK_SECRET>` | Receive raw RFC 822 MIME or parsed JSON email over HTTPS |
| `GET /api/v1/admin/status` | `Authorization: Bearer <ADMIN_SECRET>` | Server uptime, Redis status, and runtime config (returns `404` if unset/invalid) |

### Security Model for Secrets

- **Per-Inbox Bearer Tokens**: Generated via `crypto.randomBytes(32)`, returned once on creation or rotation, hashed with SHA-256 before storing in Redis, and verified using `crypto.timingSafeEqual`. Missing or invalid tokens return `404` to prevent address probing.
- **Scoped Developer API Keys (`tw_live_...`)**: Stored in Redis as SHA-256 hashes with automatic TTL expiration (`API_KEY_TTL_DAYS`). Elevate rate limits from 20 to 120 inbox creations/hr and 120 to 600 reads/min.
- **Webhook & Admin Secrets**: Configured solely via server environment variables (`INBOUND_WEBHOOK_SECRET`, `ADMIN_SECRET`) and verified in constant time.

## Receiving Free Real Emails Without Port 25 (Cloudflare Email Routing)

If you host Throwaway on a PaaS or cloud container where inbound TCP port 25 is blocked, you can receive **100% free real emails** from Gmail, Outlook, and any external sender using **Cloudflare Email Routing** (included free on any domain using Cloudflare DNS) forwarded to `POST /api/v1/inbound/email`:

1. Set `DOMAINS=yourdomain.com` and `INBOUND_WEBHOOK_SECRET=<strong-random-secret>` in `.env` / server secrets.
2. Enable **Email Routing** in your Cloudflare dashboard for `yourdomain.com` and set a **Catch-All** rule routed to a **Cloudflare Email Worker**:

```js
export default {
  async email(message, env) {
    const raw = await new Response(message.raw).text();
    const res = await fetch("https://yourdomain.com/api/v1/inbound/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Webhook-Secret": env.INBOUND_WEBHOOK_SECRET,
      },
      body: JSON.stringify({
        to: message.to,
        from: message.from,
        raw,
      }),
    });
    if (res.status === 404) {
      message.setReject("Mailbox not found");
    }
  },
};
```

3. Bind `INBOUND_WEBHOOK_SECRET` as an encrypted secret in the Cloudflare Worker settings. Incoming emails are verified, parsed by `mailparser`, sanitized by `sanitize-html`, pushed to SSE listeners, and auto-deleted on inbox expiry.

