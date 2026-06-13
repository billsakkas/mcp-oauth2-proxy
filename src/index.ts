import { Hono, type Context } from 'hono'
import { serve } from '@hono/node-server'
import { timingSafeEqual } from 'crypto'

function env(key: string): string {
  const v = process.env[key]
  if (!v) throw new Error(`Missing required env var: ${key}`)
  return v
}

// Constant-time comparison to prevent timing attacks on token checks
function safeEqual(a: string, b: string): boolean {
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b))
  } catch {
    return false
  }
}

// Headers that must not be forwarded upstream (hop-by-hop)
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'transfer-encoding',
  'te', 'trailer', 'upgrade', 'proxy-connection',
])

const app = new Hono()

// RFC 8414 — OAuth 2.0 Authorization Server Metadata
// Claude hits this first to discover the token endpoint
app.get('/.well-known/oauth-authorization-server', (c) => {
  const base = env('PUBLIC_URL')
  return c.json({
    issuer: base,
    token_endpoint: `${base}/oauth/token`,
    grant_types_supported: ['client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
  })
})

// OAuth 2.0 token endpoint — client_credentials grant only
app.post('/oauth/token', async (c) => {
  const body = await c.req.parseBody() as Record<string, string>
  const { grant_type, client_id, client_secret } = body

  if (
    grant_type !== 'client_credentials' ||
    !safeEqual(client_id ?? '', env('OAUTH_CLIENT_ID')) ||
    !safeEqual(client_secret ?? '', env('OAUTH_CLIENT_SECRET'))
  ) {
    return c.json({ error: 'invalid_client', error_description: 'Invalid credentials' }, 401)
  }

  return c.json({
    access_token: env('PROXY_ACCESS_TOKEN'),
    token_type: 'bearer',
    expires_in: 86400 * 365, // static token — no rotation needed for this use case
  })
})

async function mcpProxy(c: Context) {
  // Validate Bearer token from Claude
  const auth = c.req.header('authorization') ?? ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : ''
  if (!safeEqual(token, env('PROXY_ACCESS_TOKEN'))) {
    return c.json({ error: 'invalid_token' }, 401)
  }

  // Build upstream URL: strip /mcp prefix, append to COOLIFY_MCP_URL
  const parsed = new URL(c.req.url)
  const subPath = parsed.pathname.replace(/^\/mcp/, '')
  const targetUrl = env('COOLIFY_MCP_URL').replace(/\/$/, '') + subPath + parsed.search

  // Forward only safe headers; inject Coolify + CF Zero Trust credentials
  const fwdHeaders: Record<string, string> = {
    'content-type': c.req.header('content-type') ?? 'application/json',
    'accept': c.req.header('accept') ?? 'application/json',
    'authorization': `Bearer ${env('COOLIFY_BEARER_TOKEN')}`,
    'cf-access-client-id': env('CF_ACCESS_CLIENT_ID'),
    'cf-access-client-secret': env('CF_ACCESS_CLIENT_SECRET'),
  }

  const sessionId = c.req.header('mcp-session-id')
  if (sessionId) fwdHeaders['mcp-session-id'] = sessionId

  const method = c.req.method
  const hasBody = method !== 'GET' && method !== 'DELETE' && method !== 'HEAD'

  const upstreamRes = await fetch(targetUrl, {
    method,
    headers: fwdHeaders,
    body: hasBody ? await c.req.arrayBuffer() : undefined,
  })

  // Strip hop-by-hop headers before forwarding response
  const responseHeaders = new Headers()
  upstreamRes.headers.forEach((val, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) responseHeaders.set(key, val)
  })

  // Return response with body streamed (handles both JSON-RPC and SSE)
  return new Response(upstreamRes.body, {
    status: upstreamRes.status,
    headers: responseHeaders,
  })
}

// Handle both /mcp (no trailing path) and /mcp/* (with subpath)
app.all('/mcp', mcpProxy)
app.all('/mcp/*', mcpProxy)

const port = parseInt(process.env.PORT ?? '3000')
serve({ fetch: app.fetch, port, hostname: '0.0.0.0' }, () => {
  console.log(`MCP OAuth2 proxy listening on :${port}`)
})
