import { Hono, type Context } from 'hono'
import { serve } from '@hono/node-server'
import { createHash, randomBytes, timingSafeEqual } from 'crypto'

function env(key: string): string {
  const v = process.env[key]
  if (!v) throw new Error(`Missing required env var: ${key}`)
  return v
}

function safeEqual(a: string, b: string): boolean {
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b))
  } catch {
    return false
  }
}

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'transfer-encoding',
  'te', 'trailer', 'upgrade', 'proxy-connection',
])

// In-memory store for pending auth codes (PKCE, 5-min TTL)
interface PendingCode {
  codeChallenge: string
  codeChallengeMethod: string
  redirectUri: string
  clientId: string
  expires: number
}
const pendingCodes = new Map<string, PendingCode>()
setInterval(() => {
  const now = Date.now()
  for (const [code, data] of pendingCodes) {
    if (data.expires < now) pendingCodes.delete(code)
  }
}, 60_000)

const app = new Hono()

// RFC 8414 — OAuth 2.0 Authorization Server Metadata
app.get('/.well-known/oauth-authorization-server', (c) => {
  const base = env('PUBLIC_URL')
  return c.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/oauth/token`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'client_credentials'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
  })
})

// Authorization endpoint — validates client, issues code, redirects immediately
// (no interactive login needed; this proxy is single-tenant)
app.get('/authorize', (c) => {
  const q = c.req.query()
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state } = q

  if (response_type !== 'code' || client_id !== env('OAUTH_CLIENT_ID') || !redirect_uri || !code_challenge) {
    return c.json({ error: 'invalid_request' }, 400)
  }

  const code = randomBytes(32).toString('hex')
  pendingCodes.set(code, {
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method ?? 'S256',
    redirectUri: redirect_uri,
    clientId: client_id,
    expires: Date.now() + 5 * 60 * 1000,
  })

  const dest = new URL(redirect_uri)
  dest.searchParams.set('code', code)
  if (state) dest.searchParams.set('state', state)

  return c.redirect(dest.toString())
})

// Token endpoint — handles both authorization_code (PKCE) and client_credentials
app.post('/oauth/token', async (c) => {
  const body = await c.req.parseBody() as Record<string, string>
  const { grant_type, client_id, client_secret, code, redirect_uri, code_verifier } = body

  if (grant_type === 'authorization_code') {
    const pending = pendingCodes.get(code)
    if (!pending || Date.now() > pending.expires) {
      return c.json({ error: 'invalid_grant' }, 401)
    }
    pendingCodes.delete(code)

    if (client_id !== pending.clientId || redirect_uri !== pending.redirectUri) {
      return c.json({ error: 'invalid_grant' }, 401)
    }

    // Verify PKCE S256: BASE64URL(SHA256(code_verifier)) must equal code_challenge
    const computed = createHash('sha256').update(code_verifier ?? '').digest('base64url')
    if (!safeEqual(computed, pending.codeChallenge)) {
      return c.json({ error: 'invalid_grant' }, 401)
    }

    return c.json({
      access_token: env('PROXY_ACCESS_TOKEN'),
      token_type: 'bearer',
      expires_in: 86400 * 365,
    })
  }

  if (grant_type === 'client_credentials') {
    if (
      !safeEqual(client_id ?? '', env('OAUTH_CLIENT_ID')) ||
      !safeEqual(client_secret ?? '', env('OAUTH_CLIENT_SECRET'))
    ) {
      return c.json({ error: 'invalid_client' }, 401)
    }

    return c.json({
      access_token: env('PROXY_ACCESS_TOKEN'),
      token_type: 'bearer',
      expires_in: 86400 * 365,
    })
  }

  return c.json({ error: 'unsupported_grant_type' }, 400)
})

async function mcpProxy(c: Context) {
  const auth = c.req.header('authorization') ?? ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : ''
  if (!safeEqual(token, env('PROXY_ACCESS_TOKEN'))) {
    return c.json({ error: 'invalid_token' }, 401)
  }

  const parsed = new URL(c.req.url)
  const subPath = parsed.pathname.replace(/^\/mcp/, '')
  const targetUrl = env('COOLIFY_MCP_URL').replace(/\/$/, '') + subPath + parsed.search

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

  const responseHeaders = new Headers()
  upstreamRes.headers.forEach((val, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) responseHeaders.set(key, val)
  })

  return new Response(upstreamRes.body, {
    status: upstreamRes.status,
    headers: responseHeaders,
  })
}

app.all('/mcp', mcpProxy)
app.all('/mcp/*', mcpProxy)

const port = parseInt(process.env.PORT ?? '3000')
serve({ fetch: app.fetch, port, hostname: '0.0.0.0' }, () => {
  console.log(`MCP OAuth2 proxy listening on :${port}`)
})
