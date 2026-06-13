# mcp-oauth2-proxy

Minimal OAuth 2.0 proxy that sits between Claude.ai / Claude iOS and a Coolify MCP server behind Cloudflare Zero Trust.

```
Claude (iOS/Web/Mac)
  │  OAuth 2.0 (auth code + PKCE  or  client_credentials)
  ▼
mcp-proxy.example.com
  │  Bearer token + CF Service Token headers injected
  ▼
coolify.example.com/mcp  ← behind Zero Trust
```

Built with [Hono](https://hono.dev) + Node.js. ~120 lines, no framework overhead.

## Env vars

| Variable | Description |
|---|---|
| `PUBLIC_URL` | Public URL of this proxy, no trailing slash |
| `OAUTH_CLIENT_ID` | Client ID Claude uses for OAuth |
| `OAUTH_CLIENT_SECRET` | Client secret for `client_credentials` grant |
| `PROXY_ACCESS_TOKEN` | Static bearer token issued to Claude after OAuth — generate with `openssl rand -hex 32` |
| `COOLIFY_MCP_URL` | Upstream MCP endpoint, e.g. `https://coolify.example.com/mcp` |
| `COOLIFY_BEARER_TOKEN` | Coolify API token |
| `CF_ACCESS_CLIENT_ID` | Cloudflare Zero Trust service token client ID |
| `CF_ACCESS_CLIENT_SECRET` | Cloudflare Zero Trust service token secret |
| `PORT` | Listen port (default `3000`) |

Copy `.env.example` to `.env` and fill in the values.

## Claude.ai connector setup

Settings → Connectors → Add Custom Connector:

- **URL:** `https://<your-proxy>/mcp`
- **Client ID:** value of `OAUTH_CLIENT_ID`
- **Client Secret:** value of `OAUTH_CLIENT_SECRET`

Claude discovers the OAuth endpoints automatically via `/.well-known/oauth-authorization-server`.

## Cloudflare Zero Trust

Create a new Access Application scoped to `<coolify-host>/mcp` (not the root domain) with a **Service Auth** policy for a service token. Set that token's client ID and secret as `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`.

## Development

```bash
cp .env.example .env  # fill in values
npm install
npm run dev
```

## Deployment

Dockerfile included. Deploy anywhere that runs containers — the repo is set up for Coolify with auto-deploy on push to `main`.
