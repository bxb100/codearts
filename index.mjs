// CodeArts (华为云码道 代码智能体) as a magpie / OpenCode provider plugin.
//
// CodeArts, Huawei Cloud's coding agent (码道), serves its models over an
// OpenAI-compatible Chat Completions API at
// https://snap-access.cn-north-4.myhuaweicloud.com/api/v2 — but unlike a plain
// OpenAI-compatible provider it does NOT take an API key. Requests are signed
// with临时 AK/SK/security-token credentials using Huawei's SDK-HMAC-SHA256
// scheme, and those credentials are obtained by signing in to Huawei Cloud
// with OAuth.
//
// This plugin implements exactly that flow, mirroring the real CodeArts agent
// (and the `Ebony-Vinyl/dsh-our-free-model` CodeArts channel, which this plugin
// is modelled on):
//
//   1. `auth.methods[0]` is `{ type: "oauth" }`. `authorize()` starts a
//      loopback callback server on 127.0.0.1 (port >= 10000), returns the
//      Huawei Cloud portal URL for magpie to open, and completes with the
//      credentials once the browser is redirected back with an auth code.
//   2. The sign-in is PKCE: a random code_verifier is sent to the STS token
//      endpoint together with the code and the S256 challenge's pre-image. It
//      is also a DPoP flow: a fresh ES256 (P-256) key pair signs each token
//      request, and the private key JWK is persisted so refresh requests can
//      sign with it too.
//   3. STS answers with rotating AK/SK/security-token credentials plus a
//      refresh_token. The whole credential (including the verifier and DPoP
//      key) is stored as JSON in the account's `access` field.
//   4. `auth.refresh` silently renews before expiry via `grant_type =
//      refresh_token`; the same verifier and DPoP key are reused.
//   5. Every model request is signed with SDK-HMAC-SHA256 in the loader's
//      `fetch`, and the account's live model list + quota are read from
//      signed GETs.
//
// It imitates @magpie-community/opencode-workbuddy-auth for structure but
// replaces its browser sign-in + bearer-token requests with CodeArts' OAuth +
// signed-request flow. See README.md / DESIGN.md.

import { createServer } from "node:http"

const PROVIDER = "codearts"

// ---- endpoints & flow constants --------------------------------------------

// Chat Completions base (loader `baseURL`). A chat goes to
// `${CHAT_API_BASE}/chat/completions`.
const CHAT_API_BASE = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2"
// Snap-access manager host: model list + account/quota + legacy ticket polling.
const SNAP_HOST = "https://snap-access.cn-north-4.myhuaweicloud.com"
const SNAP_MODEL_BUILTIN_URL = `${SNAP_HOST}/v1/model/builtin`
const SNAP_STATISTICS_URL = `${SNAP_HOST}/snap-manager/v1/statistics/plugin`
const CREDENTIAL_ENDPOINT = `${SNAP_HOST}/snap-manager/v1/login/ticket`
// opengw gateway config: the benefit/free-quota model set.
const OPENGW_GATEWAY_CONFIG_URL = "https://opengw.developer.huaweicloud.com/api/v1/gateway/config"
// The benefit (free-quota) pool a `maas_type: benefit` chat is billed against.
// It is a daily token allowance, separate from the credit packages above, so
// without it a free model's spend is invisible in the usage panel.
const BENEFIT_BALANCE_URL = "https://opengw.developer.huaweicloud.com/api/v1/user/tokens/balance"

// check in
const OPENGW_CLAIM_URL = "https://opengw.developer.huaweicloud.com/api/v1/benefit/claim"
const BENEFIT_GATEWAY_CONFIG_URL = `${SNAP_HOST}/v1/benefit-gateway-config`
const SNAP_OPS_BASE = `${SNAP_HOST}/v1/ops`
const SNAP_OPS_DELIVERY_URL = `${SNAP_OPS_BASE}/delivery?channel=IDE`
const SNAP_OPS_CLAIM_URL = `${SNAP_OPS_BASE}/claim`
const SNAP_OPS_CONFIRM_URL = `${SNAP_OPS_BASE}/confirm`
const OPS_CAMPAIGN_ID = 1 // the USER_LOGIN campaign: 每日签到领1000积分
const OPS_REREAD_ATTEMPTS = 3
const OPS_REREAD_DELAY_MS = 400

// OAuth portal (new IAM flow) and the STS token endpoint.
const PORTAL_AUTHORIZE_BASE = "https://codearts.huaweicloud.com/portal/authorize"
const PORTAL_LOGIN_BASE = "https://codearts.huaweicloud.com/portal/login"
const STS_TOKEN_ENDPOINT = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"

// OAuth client id (equals the plugin's URI scheme) and local callback path.
const CLIENT_ID = "codearts-agent"
const REDIRECT_PATH = "/oauth/callback"
// What the portal expects the calling plugin to be called (reverse-engineered
// constants — the plugin/version match the real IDE extension, not this package).
const LOGIN_PLUGIN_NAME = "snap_AIIDE"
const LOGIN_PLUGIN_VERSION = "5.2.0"
const OAUTH_THEME = "2" // activeColorTheme.kind: 2 = Dark
const OAUTH_LOCALE = "zh-cn"


const TOKEN_TIMEOUT_MS = 60_000
const REQUEST_TIMEOUT_MS = 30_000
const OAUTH_CALLBACK_TIMEOUT_MS = 180_000
const MIN_CALLBACK_PORT = 10_000
const LOGIN_POLL_ATTEMPTS = 120

// Renew this long before the credential expires.
const REFRESH_LEAD_MS = 30 * 60 * 1000

// Upstream keeps at most 3 live sessions per account; the 4th answer is HTTP
// 400 `TM.00001041` (并发会话数已达上限). Wait for the queue instead of
// handing that to the caller, and cap our own in-flight requests first.
const QUEUE_STATUS_URL = `${SNAP_HOST}/api/v1/queue/status`
const QUEUE_RETRY_DELAY_MS = 10_000
const QUEUE_MAX_ATTEMPTS = 180
const ACCOUNT_MAX_INFLIGHT = 3
// How much of a 200 body to read before deciding it is not a queue rejection.
// A queue error is the stream's first event, so this stays tiny.
const SSE_PEEK_LIMIT = 8 * 1024

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
  "Access-Control-Max-Age": "86400",
}

// Benefits (free-quota) models require `maas_type: benefit` as a *signed*
// header, or the backend answers InferHub.002002009.404 "model is not
// registered". The authoritative list comes from opengw gateway/config at
// runtime; these are the known defaults so a cold start still works.
//
// The dated ids are measured behaviour, not a guess: `deepseek-v4-flash-0731`
// answers 200 against the free token pool with the signed benefit header, the
// bare `deepseek-v4-flash` answers `InferHub.4005.200 unsupported model` with
// that header, and the dated id answers `InferHub.002002009.404 not registered`
// without it. The free models are therefore published under their raw dated ids.
const BENEFIT_MODEL_FALLBACK = [
  "glm-5.3-flash",
  "deepseek-v4.1-flash",
  "deepseek-v4-flash-0731",
  "deepseek-v4-pro-0813",
]
let benefitModelIds = [...BENEFIT_MODEL_FALLBACK]

// Context windows (in tokens), keyed by the exact chat model id. Models
// without an entry leave the window to the backend's default.
const CONTEXT_WINDOWS = {
  "GLM-5.2": 202752,
  "glm-5.3-flash": 1048576,
  "deepseek-v4-flash": 1048576,
  "deepseek-v4-pro": 1048576,
  "deepseek-v4.1-flash": 1000000,
}

// The models offered before (or instead of) the account's own live list.
// Ids are exactly what the backend registers: the free models carry their dated
// ids, because the benefit header only accepts those. `GLM-5` is gone — the
// endpoint answers `InferHub.002002009.404` for it, so listing it only produced
// a picker row that could not be called.
const CATALOG = [
  { id: "GLM-5.2", name: "GLM-5.2" },
  { id: "GLM-5.1", name: "GLM-5.1" },
  { id: "glm-5.3-flash", name: "GLM-5.3 Flash" },
  { id: "openpangu-2.0-flash", name: "openPangu 2.0 Flash" },
  { id: "openpangu-2.0-pro", name: "openPangu 2.0 Pro" },
  { id: "deepseek-v4-flash-0731", name: "DeepSeek V4 Flash" },
  { id: "deepseek-v4-pro-0813", name: "DeepSeek V4 Pro" },
  { id: "deepseek-v4.1-flash", name: "DeepSeek V4.1 Flash" },
]

// The gateway refuses a bigger output budget (RANGE_VALIDATOR: max_completion
// tokens must be between 0 and 65536). Declaring no limit made callers pass
// their own default, which is over it.
const MAX_OUTPUT_TOKENS = 65_536
// Thinking must be asked for EXPLICITLY: left to the default, the gateway
// streams the model's reasoning inside `content` itself, so a caller shows the
// thinking as the answer. With `thinking: { type: "enabled" }` the reasoning
// goes to `reasoning_content` and `content` carries only the reply (measured:
// default -> content and reasoning both "我们需要回答…"; enabled -> content
// "1+1等于2。", reasoning kept apart).
const ENABLE_THINKING = { type: "enabled" }

// ---- small helpers ---------------------------------------------------------

const firstOf = (...vs) => vs.find((v) => typeof v === "string" && v.trim())?.trim() ?? ""

const asRecord = (v) => (typeof v === "object" && v !== null && !Array.isArray(v) ? v : {})

function safeJson(text) {
  try {
    const parsed = JSON.parse(text)
    return typeof parsed === "object" && parsed !== null ? parsed : null
  } catch {
    return null
  }
}

function num(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v
  if (typeof v === "string" && v.trim()) {
    const n = Number(v)
    if (Number.isFinite(n)) return n
  }
  return 0
}


// prettify is a model id as a name: openpangu-2.0-flash -> "Openpangu 2.0 Flash"
function prettify(id) {
  return String(id)
    .split(/[-_]/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ")
}

// dropDateSuffix strips a trailing 4-digit version tag: deepseek-v4-flash-0731
// -> deepseek-v4-flash. Only for the display name and the CONTEXT_WINDOWS
// lookup. It must not rewrite ids sent to the backend: the dated form is the
// registered free model and the bare form is a different, paid one.
const normalizeModelId = (id) => id.replace(/(?<=.)-\d{4}$/, "")

// ---- WebCrypto primitives --------------------------------------------------

const utf8 = (s) => new TextEncoder().encode(s)

const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("")

const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n))

const randomHex = (n) => hex(randomBytes(n))

function b64url(u8) {
  let s = ""
  for (const b of u8) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

// `data` is bytes, never a string: `new Uint8Array("…")` would coerce the
// string to a number and hash as an empty body, so the signature would disagree
// with the body actually sent (`APIG.0301 … body hash mismatch`).
async function sha256Hex(data) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)))
}

async function hmacSha256Hex(key, data) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
  return hex(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data)))
}

/** PKCE pair: a random 48-byte base64url verifier + its S256 challenge. */
async function generatePkcePair() {
  const codeVerifier = b64url(randomBytes(48))
  const digest = await crypto.subtle.digest("SHA-256", utf8(codeVerifier))
  return { codeVerifier, codeChallenge: b64url(new Uint8Array(digest)) }
}

/** An ES256 (P-256) DPoP key pair as JWKs, from a private JWK. */
function keyPairFromStoredJwk({ x, y, d }) {
  return {
    privateKeyJwk: { kty: "EC", crv: "P-256", x, y, d },
    publicKeyJwk: { kty: "EC", crv: "P-256", x, y },
  }
}

async function generateDpopKeyPair() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  return keyPairFromStoredJwk(await crypto.subtle.exportKey("jwk", pair.privateKey))
}

/** Sign a `dpop+jwt` proof (htm=method, htu=URL) with the DPoP private key. */
async function signDpopJws(keyPair, htm, htu) {
  const header = { alg: "ES256", typ: "dpop+jwt", jwk: keyPair.publicKeyJwk }
  const payload = { htm, htu, iat: Math.floor(Date.now() / 1000), jti: randomHex(32) }
  const signingInput = `${b64url(utf8(JSON.stringify(header)))}.${b64url(utf8(JSON.stringify(payload)))}`
  const key = await crypto.subtle.importKey(
    "jwk", keyPair.privateKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
  )
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(signingInput))
  // WebCrypto ECDSA returns raw r||s, which is exactly the JWS ES256 format.
  return `${signingInput}.${b64url(new Uint8Array(sig))}`
}

// ---- Huawei SDK-HMAC-SHA256 request signing --------------------------------

/**
 * Sign a Huawei request; returns the header map to merge into the request.
 * `body` is bytes or a string. Extra headers (e.g. `maas_type: benefit`)
 * participate in the canonical request and must be sent verbatim, or the
 * server rejects the signature.
 */
async function signRequestHuawei(ak, sk, securityToken, method, urlStr, body, extraHeaders, dateStampOverride) {
  method = method.toUpperCase()
  const url = new URL(urlStr)
  const uri = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`
  const dateStamp = dateStampOverride
    ?? new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")
  const payloadHash = await sha256Hex(typeof body === "string" ? utf8(body) : body)

  const headers = new Map([
    ["host", url.host],
    ["x-sdk-date", dateStamp],
    ["x-sdk-content-sha256", payloadHash],
    ["x-security-token", securityToken],
    ...Object.entries(extraHeaders ?? {}),
  ])
  if (method !== "GET") headers.set("content-type", "application/json")

  const signedHeaders = [...headers.keys()].sort()
  const canonicalRequest = [
    method, uri, url.search.slice(1),
    signedHeaders.map((k) => `${k}:${headers.get(k)}`).join("\n"), "",
    signedHeaders.join(";"), payloadHash,
  ].join("\n")
  const stringToSign = `SDK-HMAC-SHA256\n${dateStamp}\n${await sha256Hex(utf8(canonicalRequest))}`
  const signature = await hmacSha256Hex(utf8(sk), utf8(stringToSign))
  headers.set(
    "Authorization",
    `SDK-HMAC-SHA256 Access=${ak},SignedHeaders=${signedHeaders.join(";")},Signature=${signature}`,
  )
  return headers
}

/** The headers to send for a request signed with `cred` (`host` is the fetcher's job). */
async function signHeaders(cred, method, url, body, extraHeaders) {
  const signed = await signRequestHuawei(
    cred.access_key_id, cred.secret_access_key, cred.security_token, method, url, body, extraHeaders,
  )
  signed.delete("host")
  return new Headers(signed)
}

// ---- OAuth token exchange --------------------------------------------------

/**
 * Normalize an STS token response into a persisted CodeArts credential. On a
 * refresh, `prev` is the credential being replaced: the rotating fields come
 * from STS, the account's own identity (session id, a legacy login's ids, and
 * the refresh token when STS does not rotate it) carries over.
 */
function credentialFromTokenResponse(token, codeVerifier, keyPair, prev = {}) {
  const c = token.credentials ?? {}
  const next = {
    access_key_id: c.access_key_id ?? "",
    secret_access_key: c.secret_access_key ?? "",
    security_token: c.security_token ?? "",
    expires_at: c.expiration ?? "",
    refresh_token: token.refresh_token || prev.refresh_token,
    code_verifier: codeVerifier,
    dpop_private_key_jwk: keyPair.privateKeyJwk,
    // Minted once and kept across refreshes, so one account keeps one session.
    session_id: prev.session_id || randomHex(16),
  }
  for (const k of ["domain_id", "user_id", "user_name"]) {
    if (prev[k]) next[k] = prev[k]
  }
  return next
}

/** The auth record magpie stores for a credential (it lives in `access`). */
function authRecord(cred) {
  return { access: JSON.stringify(cred), refresh: cred.refresh_token, expires: expiresFromCredential(cred) }
}

/** The credential a sign-in carries; magpie keeps it in the `access` field. */
function credentialOf(auth) {
  if (!auth || auth.type !== "oauth") return null
  const raw = typeof auth.access === "string" ? auth.access : ""
  if (!raw) return null
  const cred = safeJson(raw)
  return cred && typeof cred.access_key_id === "string" && cred.access_key_id ? cred : null
}

function expiresFromCredential(cred) {
  if (cred?.expires_at) {
    const parsed = Date.parse(cred.expires_at)
    if (!Number.isNaN(parsed)) return parsed
  }
  return Date.now() + 86_400_000
}

/** POST the STS token endpoint with a DPoP proof. */
async function requestToken(body, keyPair, fetcher) {
  const dpop = await signDpopJws(keyPair, "POST", STS_TOKEN_ENDPOINT)
  let response
  try {
    response = await fetcher(STS_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { DPoP: dpop, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    })
  } catch (e) {
    throw new Error(`CodeArts token request network error: ${String(e)}`)
  }
  const data = await response.json().catch(() => null)
  if (!response.ok || !data?.credentials) {
    const message = `CodeArts token request failed: ${response.status}${data ? ` ${JSON.stringify(data)}` : ""}`
    // Only refresh_token invalidation is terminal; a transient DPoP rejection
    // must not permanently mark the account.
    const errorCode = String(data?.error_code ?? "")
    if (data?.error === "invalid_grant" || errorCode.includes("ExpiredRefreshToken")) {
      throw Object.assign(new Error(message), { signIn: "expired" })
    }
    throw new Error(message)
  }
  return data
}

/** Refresh a stored credential, reusing its verifier + DPoP private key. */
async function refreshCredential(cred, fetcher) {
  const refreshToken = firstOf(cred.refresh_token)
  if (!refreshToken || !cred.code_verifier || !cred.dpop_private_key_jwk) {
    throw new Error("CodeArts: credential cannot be refreshed (missing refresh_token/code_verifier/dpop key)")
  }
  const keyPair = keyPairFromStoredJwk(cred.dpop_private_key_jwk)
  const token = await requestToken({
    client_id: CLIENT_ID,
    code_verifier: cred.code_verifier,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  }, keyPair, fetcher)
  return credentialFromTokenResponse(token, cred.code_verifier, keyPair, cred)
}

// ---- OAuth login: URL + loopback callback ----------------------------------

const portalLoginResultUrl = (ok) =>
  `${PORTAL_LOGIN_BASE}?login_succeed=${ok}&uri_scheme=${CLIENT_ID}&locale=${OAUTH_LOCALE}`

/** Build the Huawei Cloud portal authorize URL (params mirror the real IDE). */
function buildOAuthLoginUrl(port, pkce, ticketId) {
  return `${PORTAL_AUTHORIZE_BASE}?theme=${OAUTH_THEME}&locale=${OAUTH_LOCALE}`
    + `&uri_scheme=${CLIENT_ID}&client_id=${CLIENT_ID}&port=${port}`
    + `&code_challenge=${pkce.codeChallenge}&code_challenge_method=SHA-256`
    + `&ticket_id=${ticketId}&plugin-name=${LOGIN_PLUGIN_NAME}&plugin-version=${LOGIN_PLUGIN_VERSION}`
}

/**
 * Legacy fallback: poll the ticket endpoint until a credential arrives. The
 * endpoint answers in one of two shapes (`credential` or `result`).
 */
async function pollForCredential(ticketId, secret, fetcher) {
  const url = `${CREDENTIAL_ENDPOINT}?ticket_id=${encodeURIComponent(ticketId)}&secret=${encodeURIComponent(secret)}`
  const headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "plugin-name": LOGIN_PLUGIN_NAME,
    "plugin-version": LOGIN_PLUGIN_VERSION,
  }
  for (let i = 0; i < LOGIN_POLL_ATTEMPTS; i++) {
    if (i > 0) await delay(1000)
    const data = await fetcher(url, { method: "GET", headers })
      .then((res) => (res.ok ? res.json() : null))
      .catch(() => null)
    const c = data?.credential
    const token = c?.securitytoken ?? c?.securityToken
    if (c?.access && token) {
      return {
        access_key_id: c.access,
        secret_access_key: c.secret ?? "",
        security_token: token,
        expires_at: c.expires_at ?? c.expiresAt ?? "",
        domain_id: data.domain_id ?? "",
        user_id: data.user_id ?? "",
        user_name: data.user_name ?? "",
      }
    }
    const r = data?.result
    if (r?.accessKeyId && r.securityToken) {
      return {
        access_key_id: r.accessKeyId,
        secret_access_key: r.secretAccessKey ?? "",
        security_token: r.securityToken,
        expires_at: r.expiration ?? r.expiresAt ?? "",
      }
    }
  }
  throw new Error("CodeArts login timed out")
}

/**
 * Start an OAuth flow and return its login URL immediately (magpie opens it).
 * A loopback server on 127.0.0.1 (port >= 10000) waits for the browser to be
 * redirected back; `result` resolves to the credential once STS answers and is
 * rejected on failure or timeout. The server is closed as soon as it settles.
 */
async function startOAuthFlow(fetcher) {
  const ticketId = randomHex(32)
  const pkce = await generatePkcePair()
  const keyPair = await generateDpopKeyPair()
  let settle
  const result = new Promise((resolve, reject) => { settle = { resolve, reject } })

  const server = createServer((request, response) => {
    const port = request.socket.localPort
    const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`)
    const redirect = (to) => response.writeHead(307, { ...CORS_HEADERS, Location: to }).end()
    if (!url.pathname.startsWith(REDIRECT_PATH)) {
      response.writeHead(404).end("Not found")
      return
    }
    if (request.method === "OPTIONS") {
      response.writeHead(204, CORS_HEADERS).end()
      return
    }

    // Legacy fallback: the portal decided OAuth is unavailable and redirected
    // with a secret; poll the ticket endpoint in the background.
    const secret = url.searchParams.get("secret")
    if (secret) {
      redirect(url.searchParams.get("redirect") ?? portalLoginResultUrl(true))
      pollForCredential(ticketId, secret, fetcher).then(settle.resolve, settle.reject)
      return
    }

    // New IAM OAuth: an authorization code to exchange at STS.
    const code = url.searchParams.get("code")
    if (!code) {
      response.writeHead(400).end("Missing authorization code or secret")
      return
    }
    requestToken({
      client_id: CLIENT_ID,
      code,
      code_verifier: pkce.codeVerifier,
      grant_type: "authorization_code",
      redirect_uri: `http://127.0.0.1:${port}${REDIRECT_PATH}`,
    }, keyPair, fetcher).then(
      (token) => {
        redirect(portalLoginResultUrl(true))
        settle.resolve(credentialFromTokenResponse(token, pkce.codeVerifier, keyPair))
      },
      (error) => {
        redirect(portalLoginResultUrl(false))
        settle.reject(error)
      },
    )
  })

  // Listen on a free port; the portal wants one >= 10000, so retry on a random
  // high port if the OS hands out a lower one.
  const port = await new Promise((resolve, reject) => {
    server.once("error", reject)
    const listen = (wanted) => server.listen(wanted, "127.0.0.1", () => {
      const { port } = server.address()
      if (port >= MIN_CALLBACK_PORT) resolve(port)
      else server.close(() => listen(MIN_CALLBACK_PORT + Math.floor(Math.random() * (65_536 - MIN_CALLBACK_PORT))))
    })
    listen(0)
  })

  const timer = setTimeout(() => settle.reject(new Error("CodeArts OAuth login timed out")), OAUTH_CALLBACK_TIMEOUT_MS)
  timer.unref()
  const close = async () => {
    clearTimeout(timer)
    if (server.listening) await new Promise((resolve) => server.close(() => resolve()))
  }
  // Settle in the background so an early result never becomes an unhandled
  // rejection, and so the listening socket is always released.
  result.catch(() => {}).finally(close)

  return { loginUrl: buildOAuthLoginUrl(port, pkce, ticketId), result, close }
}


// ---- signed requests to CodeArts -------------------------------------------

/** The JSON payloads of an SSE body, in arrival order, `[DONE]` skipped. */
function parseSseEvents(text) {
  const events = []
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim()
    if (!s.startsWith("data:")) continue
    const payload = s.slice(5).trim()
    if (!payload || payload === "[DONE]") continue
    const parsed = safeJson(payload)
    if (parsed) events.push(parsed)
  }
  return events
}

/** Fold streamed `choices[].delta` chunks into one OpenAI completion object. */
function completionFromChunks(events) {
  const first = events[0] ?? {}
  const content = []
  const reasoning = []
  const toolCalls = []
  let finish = null
  let usage = null
  let model = first.model
  for (const ev of events) {
    if (ev.usage) usage = ev.usage
    if (typeof ev.model === "string" && ev.model) model = ev.model
    const choice = Array.isArray(ev.choices) ? ev.choices[0] : undefined
    if (!choice) continue
    if (choice.finish_reason != null) finish = choice.finish_reason
    const delta = asRecord(choice.delta)
    if (typeof delta.content === "string") content.push(delta.content)
    if (typeof delta.reasoning_content === "string") reasoning.push(delta.reasoning_content)
    for (const call of Array.isArray(delta.tool_calls) ? delta.tool_calls : []) {
      const slotIndex = num(call.index)
      const slot = toolCalls[slotIndex] ??= { id: "", type: "function", function: { name: "", arguments: "" } }
      if (typeof call.id === "string" && call.id) slot.id = call.id
      if (typeof call.type === "string" && call.type) slot.type = call.type
      if (typeof call.function?.name === "string") slot.function.name += call.function.name
      if (typeof call.function?.arguments === "string") slot.function.arguments += call.function.arguments
    }
  }
  const message = { role: "assistant", content: content.join("") }
  if (reasoning.length > 0) message.reasoning_content = reasoning.join("")
  const calls = toolCalls.filter(Boolean)
  if (calls.length > 0) message.tool_calls = calls
  return {
    id: firstOf(first.id) || `chatcmpl-${Math.floor(Date.now() / 1000)}`,
    object: "chat.completion",
    created: num(first.created) || Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, message, finish_reason: finish ?? "stop" }],
    ...(usage ? { usage } : {}),
  }
}

/**
 * Answer a caller that asked for JSON with JSON. A stream carrying no choices is
 * an upstream error (quota, routing), and that payload must reach the caller
 * byte-for-byte rather than be turned into an empty completion.
 */
async function foldStreamToCompletion(res) {
  const text = await res.text()
  const events = parseSseEvents(text)
  if (!events.some((ev) => Array.isArray(ev.choices) && ev.choices.length > 0)) return rebuildResponse(res, text)
  const headers = streamHeaders(res.headers)
  headers.set("content-type", "application/json")
  return new Response(JSON.stringify(completionFromChunks(events)), {
    status: res.status,
    statusText: res.statusText,
    headers,
  })
}

/** Is `model` one that needs the signed `maas_type: benefit` header? */
function isBenefitModel(model) {
  return benefitModelIds.includes(model)
}

/**
 * The plugin's per-request fetch: sign the outgoing chat request with the
 * account's temporary credentials, then send it. Requests beyond the
 * account's session budget wait here, and `TM.00001041` answers are retried
 * until upstream frees a session instead of reaching the caller.
 */
async function signedFetch(cred, input, init, context) {
  // A credential already known to be beyond renewal never gets a network call:
  // every attempt would answer `APIG.0602` and burn a queue slot.
  if (context.signInDead()) return signInExpiredResponse()

  const req = input instanceof Request ? input : null
  const url = req ? req.url : String(input)
  const method = String(init?.method ?? req?.method ?? "GET").toUpperCase()
  const headers = new Headers(init?.headers ?? req?.headers)
  const signal = init?.signal ?? req?.signal
  if (signal?.aborted) throw abortError(signal)

  const source = init?.body ?? req?.clone().body
  const rawBody = source == null ? new Uint8Array() : new Uint8Array(await new Response(source).arrayBuffer())
  const raw = rawBody.length > 0 ? safeJson(new TextDecoder().decode(rawBody)) : null
  // The host hands the request down with the provider prefix on the model id
  // (`codearts/deepseek-v4.1-flash`), which the gateway does not know: it
  // answers InferHub.002002009.404 "model is not registered" (in an SSE frame
  // when streaming, so it looks like a successful reply). Strip it.
  if (raw) {
    if (typeof raw.model === "string" && raw.model.startsWith(`${PROVIDER}/`)) {
      raw.model = raw.model.slice(PROVIDER.length + 1)
    }
    // Separate reasoning only for chat requests, preserving explicit settings.
    if (Array.isArray(raw.messages) && raw.thinking === undefined) raw.thinking = ENABLE_THINKING
    // Keep the caller's output budget within the gateway's limit.
    for (const k of ["max_completion_tokens", "max_tokens"]) {
      if (typeof raw[k] === "number" && raw[k] > MAX_OUTPUT_TOKENS) raw[k] = MAX_OUTPUT_TOKENS
    }
  }
  const model = raw?.model
  // CodeArts meters a chat only when the answer comes back as an SSE stream: a
  // non-streaming 200 returns tokens yet leaves `usageTotalPackageCredit`
  // untouched, so its cost never reaches the credits pool. Send every chat
  // upstream as `stream: true` and fold the stream back into the shape the
  // caller asked for.
  const foldToCompletion = typeof model === "string" && Array.isArray(raw.messages) && raw.stream !== true
  if (foldToCompletion) raw.stream = true
  const body = raw ? utf8(JSON.stringify(raw)) : rawBody
  const extra = isBenefitModel(model) ? { maas_type: "benefit" } : undefined

  headers.set("Chat-Id", context.chatId)
  headers.set("Session-Id", context.sessionId)
  headers.set("lang", "en")
  // Signing is repeated on a credential renewal; `active` is the credential
  // the request (and its queue probes) currently go out with.
  let active = cred
  const sign = async () => {
    for (const [key, value] of await signHeaders(active, method, url, body, extra)) headers.set(key, value)
  }
  await sign()
  const request = { ...init, method, headers, ...(body.length > 0 ? { body } : {}), signal }
  const probe = () => queryQueueStatus(active, model, { ...context, signal })
  // `error` / `queue_full` never turn into a success, so stop waiting.
  const hopeless = (probed) => probed?.status === "error" || probed?.status === "queue_full"

  await context.gate.acquire()
  try {
    let renewed = false
    for (let attempt = 0; ; attempt += 1) {
      const res = await context.fetcher(url, request)
      // A 401/403 is the sign-in gone; magpie marks the account from here.
      if (res.status === 401 || res.status === 403) {
        const h = new Headers(res.headers)
        h.set("X-Magpie-Sign-In", "expired")
        return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h })
      }
      let queued = false
      let answer = null
      if (res.ok) {
        // A 200 can still be a queue rejection: CodeArts sometimes embeds the
        // error in the SSE stream instead of answering 400.
        const peeked = await peekSseQueueError(res)
        if (peeked) return foldToCompletion ? foldStreamToCompletion(peeked) : peeked
        const probed = await probe()
        if (hopeless(probed)) return queueTerminalResponse(probed)
        queued = true
      } else {
        const text = await res.text().catch(() => "")
        // The temporary credential expired between signing and sending (`APIG.0602`,
        // a bare 400 magpie does not move to another account on). Renew the
        // sign-in and send the same request again before reporting anything.
        if (!renewed && /APIG\.0602|security token has expired/i.test(text)) {
          renewed = true
          const next = await context.renewCredential()
          if (!next) return signInExpiredResponse(text)
          active = next
          await sign()
          continue
        }
        answer = rebuildResponse(res, text)
        // A non-queue error still probes the status endpoint first: some models
        // report the cap with another code yet still land in the queue.
        const probed = await probe()
        // `400` + `TM.00001041` is transient account capacity, not a bad request.
        queued = (res.status === 400 && text.includes("TM.00001041")) || probed?.status === "waiting"
        if (queued && hopeless(probed)) return answer
      }

      if (!queued || attempt >= context.queueMaxAttempts) {
        if (answer) return answer
        const waited = Math.round((context.queueRetryDelayMs * context.queueMaxAttempts) / 60_000)
        throw new Error(`CodeArts: queue wait timed out after ${waited} minutes`)
      }
      await delay(context.queueRetryDelayMs, signal)
    }
  } finally {
    context.gate.release()
  }
}

/**
 * One signed call. `signedHeaders` take part in the signature; `headers` are
 * sent as-is, unsigned. GET calls carry no body.
 */
async function signedCall(cred, fetcher, method, url, { body = "", signedHeaders, headers, signal } = {}) {
  const isGet = method === "GET"
  const sent = await signHeaders(cred, method, url, isGet ? new Uint8Array() : body, signedHeaders)
  for (const [k, v] of Object.entries(headers ?? {})) sent.set(k, v)
  const res = await fetcher(url, {
    method,
    headers: sent,
    ...(isGet ? {} : { body }),
    signal: signal ?? AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })
  return { status: res.status, text: await res.text() }
}

/** A signed GET returning the response text, or undefined on any failure. */
async function signedGet(url, cred, fetcher, headers) {
  try {
    const { status, text } = await signedCall(cred, fetcher, "GET", url, { headers })
    return status >= 200 && status < 300 ? text : undefined
  } catch {
    return undefined
  }
}

// ---- daily check-in (签到) -------------------------------------------------

const saidMatches = (said, words) => {
  const s = String(said ?? "").toLowerCase()
  return words.some((w) => s.includes(w))
}

// Fixme: normal path really need errorcode?
/** The benefit endpoints' envelope: `{error_code, result}`. */
function parseClaimReply(text) {
  const json = safeJson(text)
  const raw = String(text ?? "").trim().slice(0, 160)
  if (!json) return { ok: false, said: "", data: {}, raw }
  const code = json.error_code ?? json.errorCode ?? json.code
  const ok = code === undefined
    ? json.success === true
    : String(code) === "0000" || String(code) === "0"
  const said = firstOf(json.error_msg, json.errorMsg, json.message, json.msg)
  return { ok, said, data: asRecord(json.result ?? json.data ?? json), raw }
}

function benefitRecord(data) {
  return Boolean(firstOf(data?.channel, data?.user_id, data?.user_name) || num(data?.create_time) > 0)
}

/** The ops API's envelope, as the web app writes it: `{code: 0, data}`. */
function opsEnvelope(text) {
  const raw = String(text ?? "").trim().slice(0, 200)
  const json = safeJson(text)
  if (!json) return { ok: false, said: raw, data: {}, raw }
  const code = json.code ?? json.error_code ?? json.errorCode ?? json.resultCode
  const ok = code === undefined
    ? json.success !== false
    : [0, "0", "0000", 200, "200", "SUCCESS", "success"].includes(code)
  const said = firstOf(json.message, json.msg, json.error_msg, json.errorMsg, json.resultMsg)
  return { ok, code, said, data: asRecord(json.data ?? json.result ?? json), raw }
}

/** The first positive number under one of `keys`, through nested objects. */
function findNumber(data, keys, depth = 0) {
  if (!data || typeof data !== "object" || depth > 3) return NaN
  for (const key of keys) {
    const n = num(data[key])
    if (n > 0) return n
  }
  for (const value of Object.values(data)) {
    if (value && typeof value === "object") {
      const n = findNumber(value, keys, depth + 1)
      if (n > 0) return n
    }
  }
  return NaN
}

// What a claim's `data` calls its amount. `totalAmount`/`benefitAmount` are the
// fields the live ops API actually returns (measured 2026-10-20); the rest are
// the shapes older deployments and tests use.
const OPS_CREDIT_KEYS = ["credit", "credits", "points", "point", "rewardPoints", "benefitPoints", "totalAmount", "benefitAmount", "amount"]

/** The credits a claim/confirm answer carries, `{}` when it carries none. */
function creditExtras(source) {
  const credit = findNumber(source, OPS_CREDIT_KEYS)
  return credit > 0 ? { credit } : {}
}

/** The USER_LOGIN campaign's row, from `data.items[]`. */
function checkinItem(data) {
  const items = Array.isArray(data?.items) ? data.items : Array.isArray(data?.list) ? data.list : []
  return items.find((item) => item
    && (Number(item.campaignId ?? item.campaign_id) === OPS_CAMPAIGN_ID || item.type === "USER_LOGIN")) ?? null
}

const stateOf = (item) => String(item?.status ?? "").toUpperCase()
const isBooked = (state) => state === "CONFIRMED" || state === "CONSUMED"

/** Headers the IDE's ops route signs, and therefore must receive verbatim. */
const OPS_SIGNED_HEADERS = {
  "agent-type": "PromptCenter",
  "x-language": "zh-cn",
  "content-type": "application/json",
}

/**
 * Does this body belong to the ops API at all? The ops envelope is `{code,data}`
 * (or a bare `{data:{items}}`); the benefit endpoints answer `{error_code,result}`
 * with no `code`, and both live on the same signed credential — so a walk that
 * guesses wrong must fall through instead of reading one as the other.
 */
function looksLikeOpsAnswer(text) {
  const json = safeJson(text)
  return Boolean(json) && ("code" in json || Array.isArray(json.data?.items))
}

/**
 * Today's check-in through the IDE's signed ops route: the same walk
 * `WelfareActivityServiceImpl` performs (delivery → claim → confirm,
 * `channel: IDE`) without the popup around it. Same canonical-request contract
 * as `signedFetch`: the query string and `OPS_SIGNED_HEADERS` are part of the
 * signature, so they are sent exactly as signed.
 *
 * Returns `null` when the route is not offered to this account, so the caller
 * can report the free-benefit enrollment instead; otherwise an outcome object:
 *   claimed  — credits booked today
 *   done     — already booked today
 *   inactive — campaign not offered / switched off
 *   failed   — the vendor answered, but not with a booking
 */
async function signedOpsCheckin(cred, fetcher) {
  const ops = (method, url, body = "{}") =>
    signedCall(cred, fetcher, method, url, { body, signedHeaders: OPS_SIGNED_HEADERS })

  let delivery
  try {
    delivery = await ops("GET", SNAP_OPS_DELIVERY_URL)
  } catch {
    return null // signing/network trouble: report the benefit state instead
  }
  if (delivery.status === 401 || delivery.status === 403 || delivery.status === 404) return null
  if (delivery.status !== 200) return { outcome: "failed", message: `delivery: HTTP ${delivery.status}` }
  // A 200 that is not an ops answer means this route is not the ops API for
  // this account (a benefit reply, an HTML page…): fall through, do not guess.
  if (!looksLikeOpsAnswer(delivery.text)) return null
  const list = opsEnvelope(delivery.text)
  if (!list.ok) {
    // APIG.0101: the gateway has no such route for this account.
    if (/APIG\.0101/.test(`${list.said} ${list.raw}`)) return null
    return { outcome: "failed", message: `delivery: ${list.said || list.raw}` }
  }

  const item = checkinItem(list.data)
  if (!item) return { outcome: "inactive", message: "no USER_LOGIN campaign offered" }

  const state = stateOf(item)
  if (isBooked(state)) return { outcome: "done", ...creditExtras(item) }
  if (state !== "ELIGIBLE" && state !== "CLAIMED") {
    return { outcome: "failed", message: `unknown campaign state: ${state || "(empty)"}` }
  }

  let claimData
  if (state === "ELIGIBLE") {
    const claimed = await ops("POST", SNAP_OPS_CLAIM_URL, JSON.stringify({
      campaignId: OPS_CAMPAIGN_ID,
      channel: "IDE",
      idempotentKey: `claim_${OPS_CAMPAIGN_ID}_${Date.now()}`,
    }))
    if (claimed.status !== 200) return { outcome: "failed", message: `claim: HTTP ${claimed.status}` }
    const reply = opsEnvelope(claimed.text)
    // A claim the site refuses is a failure; a repeat claim for the same day
    // comes back as an error too, so the re-read below decides what it is.
    // `40001 尚未到达权益刷新时间` is that same "already taken today" answer.
    const sameDay =
      String(reply.code ?? "") === "40001"
      || saidMatches(reply.said, ["已领取", "已签到", "重复", "already", "duplicate", "尚未到达权益刷新时间"])
    if (!reply.ok && !sameDay) {
      return { outcome: "failed", message: `claim: ${reply.said || reply.raw}` }
    }
    claimData = reply.data
  }

  // Booking happens on confirm, so it also runs when the claim was already
  // taken today (state CLAIMED) or was a repeat.
  const confirmed = await ops("POST", SNAP_OPS_CONFIRM_URL, JSON.stringify({ campaignId: OPS_CAMPAIGN_ID }))
  if (confirmed.status !== 200) return { outcome: "failed", message: `confirm: HTTP ${confirmed.status}` }
  const booked = opsEnvelope(confirmed.text)
  if (!booked.ok) return { outcome: "failed", message: `confirm: ${booked.said || booked.raw}` }
  // The activity's own amount is the honest answer: the claim's, then the
  // campaign row's. A confirm reply can carry the account's whole credit pool
  // (`totalAmount` across every campaign), which is not what today's check-in
  // earned, so it is only the last resort.
  const result = { ...creditExtras(booked.data), ...creditExtras(item), ...creditExtras(claimData) }

  // The confirm reply *is* the booking: once it says CONFIRMED the credits are
  // in, even while the read side still serves its pre-confirm snapshot.
  // Measured 2026-10-20: right after a successful claim+confirm, `delivery`
  // answered `ELIGIBLE` for a few hundred ms — enough to make a re-read-only
  // implementation report a false "claim not booked".
  let bookedState = stateOf(booked.data)
  if (isBooked(bookedState)) return { outcome: "claimed", ...result }

  // No state in the reply: re-read, tolerating the replica lag.
  for (let attempt = 0; attempt < OPS_REREAD_ATTEMPTS; attempt++) {
    if (attempt > 0) await delay(OPS_REREAD_DELAY_MS)
    const after = await ops("GET", SNAP_OPS_DELIVERY_URL)
    const rereadItem = checkinItem(opsEnvelope(after.text).data)
    bookedState = stateOf(rereadItem)
    if (isBooked(bookedState)) return { outcome: "claimed", ...creditExtras(rereadItem), ...result }
  }
  return { outcome: "failed", message: `claim not booked: state ${bookedState || "(empty)"} after confirm` }
}

/** `enabled` off the campaign switch, or undefined when the answer lacks it. */
function gatewayEnabled(text) {
  const json = safeJson(text)
  const value = String(json?.enabled ?? json?.result?.enabled ?? json?.data?.enabled)
  return ["true", "1"].includes(value) ? true : ["false", "0"].includes(value) ? false : undefined
}

/**
 * The free-benefit enrollment, reported when the ops route is not offered. It
 * is a different thing from the credit check-in (`/api/v1/benefit/claim`
 * enrols, it does not book credits) and never invents a credit.
 */
async function benefitCheckin(cred, fetcher) {
  const failed = (message) => ({ outcome: "failed", message })
  const unreadable = (reply) => reply.said || reply.raw || "unknown answer"
  const PORTAL = "https://codearts.huaweicloud.com/portal/settings/personal-usage"
  const classify = (reply) => {
    if (saidMatches(reply.said, ["已领取", "已签到", "已经领取", "重复领取", "今日已", "already", "duplicate"])) {
      return { outcome: "inactive", message: `${reply.said}（每日积分签到在网页端 ${PORTAL}）` }
    }
    if (saidMatches(reply.said, ["未开始", "已结束", "未开启", "not started", "has ended"])) {
      return { outcome: "inactive", message: reply.said }
    }
    if (saidMatches(reply.said, ["无资格", "不具备", "不满足", "not eligible", "ineligible"])) {
      return { outcome: "ineligible", message: reply.said }
    }
    return undefined
  }
  try {
    const gate = await signedCall(cred, fetcher, "GET", BENEFIT_GATEWAY_CONFIG_URL, {
      signedHeaders: { "agent-type": "PromptCenter", "x-language": "zh-cn" },
    })
    if (gate.status === 403 || gate.status === 404) {
      return { outcome: "inactive", message: `no free-benefit program (gateway ${gate.status})` }
    }
    if (gate.status !== 200) return failed(`benefit gateway: HTTP ${gate.status}`)
    if (gatewayEnabled(gate.text) === false) return { outcome: "inactive", message: "the free-benefit program is off" }

    const state = await signedCall(cred, fetcher, "GET", OPENGW_CLAIM_URL)
    if (state.status !== 200) return failed(`benefit state: HTTP ${state.status}`)
    const before = parseClaimReply(state.text)
    if (!before.ok) return classify(before) ?? failed(`benefit state: ${unreadable(before)}`)
    // Already in: the record is there and POST only rewrites it, which is
    // why claiming every day looked like it worked and changed nothing.
    if (benefitRecord(before.data)) {
      return { outcome: "inactive", message: `免费福利已开通（每日免费 Tokens 按日清零）；每日积分签到在网页端 ${PORTAL}` }
    }

    const enrolled = await signedCall(cred, fetcher, "POST", OPENGW_CLAIM_URL)
    if (enrolled.status !== 200) return failed(`benefit claim: HTTP ${enrolled.status}`)
    const after = parseClaimReply(enrolled.text)
    if (after.ok) {
      return { outcome: "claimed", message: `免费福利已到账（每日免费 Tokens）；每日积分签到在网页端 ${PORTAL}` }
    }
    return classify(after) ?? failed(`benefit claim: ${unreadable(after)}`)
  } catch (e) {
    return failed(e?.message ?? String(e))
  }
}

// ---- upstream concurrency & queueing ---------------------------------------

/**
 * Per-account gate for in-flight requests: a burst queues here instead of
 * coming back as `TM.00001041`.
 */
function createConcurrencyGate(limit) {
  let active = 0
  const waiters = []
  return {
    acquire() {
      if (active < limit) {
        active += 1
        return Promise.resolve()
      }
      return new Promise((resolve) => waiters.push(resolve))
    },
    // A waiter inherits the released slot, so `active` only drops when nobody waits.
    release() {
      const next = waiters.shift()
      if (next) next()
      else active -= 1
    },
  }
}

function abortError(signal) {
  return signal?.reason instanceof Error ? signal.reason : new Error("CodeArts: request aborted")
}

/** Sleep, but give up as soon as the caller aborts the request. */
function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError(signal))
      return
    }
    const onAbort = () => {
      clearTimeout(timer)
      reject(abortError(signal))
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort)
      resolve()
    }, ms)
    signal?.addEventListener("abort", onAbort, { once: true })
  })
}

/**
 * Retryable queue/limit signals CodeArts can embed in a 200 SSE stream.
 * `429` is anchored to a standalone number on purpose: `InferHub.4291.200` is
 * an exhausted quota (never retryable), and its `429` prefix was mistaken for
 * the rate-limit code in the reference implementation, which then retried
 * silently for 30 minutes.
 */
function isRetryableQueueCode(text) {
  if (text.includes("TM.00001041")) return true
  return /81111|TPM|(^|[^0-9])429([^0-9]|$)|rate.?limit|too.?many.?requests/i.test(text)
}

/** Does this SSE event carry part of an answer (not just a role or a keepalive)? */
function sseEventHasContent(event) {
  const choice = Array.isArray(event?.choices) ? event.choices[0] : undefined
  if (!choice) return false
  if (choice.finish_reason != null) return true
  const delta = asRecord(choice.delta)
  if (typeof delta.content === "string" && delta.content) return true
  if (typeof delta.reasoning_content === "string" && delta.reasoning_content) return true
  return Array.isArray(delta.tool_calls) && delta.tool_calls.length > 0
}

/**
 * What a peeked 200 body means before it reaches the caller. `undefined` means
 * "not decided yet, keep reading": CodeArts can open with an empty delta and put
 * the terminal error in the next event, which is how a caller ends up with a
 * stream that stops without a `finish_reason`.
 */
function classifySseHead(text) {
  if (!text) return undefined
  if (parseSseEvents(text).some(sseEventHasContent)) return { kind: "content" }
  // A half-arrived event is not an answer yet: wait for its newline.
  if (!text.includes("\n\n")) return undefined
  // CodeArts reports a dead quota, an expired credential and the session cap
  // alike as an `error_code`, so the code is the only thing that tells them apart.
  const code = /"error_code"\s*:\s*"([^"]+)"/.exec(text)?.[1]
  if (!code) return { kind: "content" }
  if (isRetryableQueueCode(text)) return { kind: "retry" }
  // 429 and 5xx are the shapes magpie fails over to another account on; the
  // vendor's own body is kept so the agent shows its words. `InferHub.4291.x`
  // is an exhausted quota.
  return { kind: "terminal", status: /4291/.test(code) ? 429 : 502 }
}

/** Headers for a body we hand over unchanged (length/encoding no longer hold). */
function streamHeaders(headers) {
  const out = new Headers(headers)
  out.delete("content-encoding")
  out.delete("content-length")
  return out
}

/** Rebuild a consumed response so the caller still sees the upstream answer. */
function rebuildResponse(res, text) {
  return new Response(text, {
    status: res.status,
    statusText: res.statusText,
    headers: streamHeaders(res.headers),
  })
}

/**
 * Peek at a 200 body before it reaches the caller. CodeArts reports the session
 * cap, a dead quota and an expired credential as error events inside a 200 SSE
 * stream; a 200 never fails over, so the caller would see a truncated answer
 * (`Stream ended without finish_reason`) instead of a retry or another account.
 * Returns the response to hand over (the bytes read here are replayed into its
 * stream, so a real answer still reaches the caller intact), or `null` when the
 * stream is a retryable queue rejection.
 */
async function peekSseQueueError(res) {
  if (!res.body) return res
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  const buffered = []
  let seen = ""
  let verdict
  while (!(verdict = classifySseHead(seen)) && seen.length < SSE_PEEK_LIMIT) {
    const { value, done } = await reader.read()
    if (done) break
    buffered.push(value)
    seen += decoder.decode(value, { stream: true })
  }
  // Upstream's stream is discarded, not awaited: Node's reader.cancel can stay
  // pending on a live body.
  if (verdict?.kind === "retry") {
    void reader.cancel().catch(() => {})
    return null
  }
  if (verdict?.kind === "terminal") {
    void reader.cancel().catch(() => {})
    return new Response(seen, { status: verdict.status, headers: { "content-type": "text/event-stream" } })
  }
  // Replay what was read, then keep forwarding the rest with back pressure.
  const body = new ReadableStream({
    async pull(controller) {
      const next = buffered.shift()
      if (next !== undefined) {
        controller.enqueue(next)
        return
      }
      const { value, done } = await reader.read()
      if (done) controller.close()
      else controller.enqueue(value)
    },
    async cancel(reason) {
      await reader.cancel(reason).catch(() => {})
    },
  })
  return new Response(body, { status: res.status, statusText: res.statusText, headers: streamHeaders(res.headers) })
}

/** A 401 magpie reads as "this login is gone": mark it and move to the next account. */
function signInExpiredResponse(body) {
  return new Response(body ?? JSON.stringify({ error_code: "APIG.0602", error_msg: "CodeArts: the temporary credential expired; sign in again" }), {
    status: 401,
    headers: { "content-type": "application/json", "X-Magpie-Sign-In": "expired" },
  })
}

/** Answer the caller with a 429 when upstream never frees its queue. */
function queueTerminalResponse(probed) {
  return new Response(
    JSON.stringify({ error_code: "TM.00001041", error_msg: firstOf(probed.message, "CodeArts: queue is full") }),
    { status: 429, headers: { "content-type": "application/json" } },
  )
}

/** Is this session queued upstream? `undefined` when the endpoint says nothing. */
async function queryQueueStatus(cred, model, { sessionId, fetcher, signal }) {
  const url = `${QUEUE_STATUS_URL}?model=${encodeURIComponent(model)}&task_id=${encodeURIComponent(sessionId)}`
  try {
    const { status: http, text } = await signedCall(cred, fetcher, "GET", url, {
      signal,
      headers: { "x-snap-traceid": randomHex(16), "Agent-Type": "INFERHUB_AGENT", "X-Language": "en" },
    })
    if (http < 200 || http >= 300) return undefined
    const body = safeJson(text)
    if (!["waiting", "working", "error", "queue_full"].includes(body?.status)) return undefined
    return { status: body.status, message: firstOf(body.message) }
  } catch {
    return undefined
  }
}

// ---- model list & account info ---------------------------------------------

/**
 * One gateway/builtin entry into a model row. The id handed to magpie is the id
 * as published, never the date-stripped one: the free models are registered
 * only under their dated ids, so rewriting them breaks the call.
 *
 * Dedupe is by exact id. A dated id and its bare form are two different models
 * on the backend with opposite billing (`deepseek-v4-flash-0731` draws on the
 * free token pool, the bare `deepseek-v4-flash` on credits), so collapsing them
 * would hide one of the two.
 */
function parseModelInfo(m, seen) {
  const rawId = m?.model_id
  if (typeof rawId !== "string" || !rawId) return undefined
  const base = normalizeModelId(rawId)
  // Hide vision models: small context, no tool calls — not agent main models.
  // Case-insensitive: the gateway lists them lowercase (`kimi-k2.6-vl`).
  if (/-vl(-|$)/i.test(base)) return undefined
  if (seen.has(rawId)) return undefined
  seen.add(rawId)
  const rawName = m.model_name
  const name = typeof rawName === "string" && rawName ? normalizeModelId(rawName) : prettify(base)
  // gateway/config publishes per-model windows; prefer them over the static map.
  return { id: rawId, name, context: num(m.context_window) || CONTEXT_WINDOWS[base] }
}

function extractArray(text, path) {
  let value = safeJson(text)
  for (const key of path) {
    if (typeof value !== "object" || value === null) return undefined
    value = value[key]
  }
  return Array.isArray(value) ? value : undefined
}

/**
 * Fetch the account's live model list from the two signed endpoints and merge
 * them. Everything opengw gateway/config publishes is billed against the free
 * daily token pool, so each of its ids is recorded for the benefit header.
 */
async function fetchRemoteModels(cred, fetcher) {
  const models = []
  const seen = new Set()
  const sources = [
    { url: OPENGW_GATEWAY_CONFIG_URL, path: ["result", "models"], benefit: true },
    {
      url: SNAP_MODEL_BUILTIN_URL,
      path: ["builtinModels"],
      headers: { "Content-Type": "application/json", "Agent-Type": "PromptCenter", "X-Language": "zh-cn" },
    },
  ]
  for (const { url, path, benefit, headers } of sources) {
    const text = await signedGet(url, cred, fetcher, headers)
    for (const item of extractArray(text ?? "", path) ?? []) {
      const mi = parseModelInfo(item, seen)
      if (!mi) continue
      if (benefit) {
        mi.benefit = true
        if (!benefitModelIds.includes(mi.id)) benefitModelIds.push(mi.id)
      }
      models.push(mi)
    }
  }
  return models
}

const TOTAL_CREDIT_LABEL = "总积分"
/** Chinese labels for the credit metric buckets CodeArts reports. */
const CREDIT_METRIC_LABELS = {
  usageTotalPackageCredit: TOTAL_CREDIT_LABEL,
  usageBasicPackageCredit: "基础积分包",
  usageOnDemandPackageCredit: "按需积分包",
  usageBonusPackageCredit: "赠送积分包",
}

/** Compact credit counts for the display string (12345 → "1.2万"). */
function formatCredit(n) {
  const v = Math.max(0, Number.isFinite(n) ? n : 0)
  if (v >= 1e8) return `${(v / 1e8).toFixed(1)}亿`
  if (v >= 1e4) return `${(v / 1e4).toFixed(1)}万`
  return String(Math.round(v))
}

/**
 * The benefit (free-quota) daily token allowance as a usage window. Its unit is
 * tokens, not credits: a `maas_type: benefit` chat is billed against this pool
 * and never touches the credit packages. `models` scopes it to the benefit ids
 * so it counts only the models that draw on it, and `aside` keeps it out of
 * routing: exhausting the free pool leaves the paid models usable.
 */
function benefitWindow(raw, ids = []) {
  const rec = asRecord(asRecord(raw).result ?? raw)
  const limit = num(rec.daily_token_limit)
  if (limit <= 0) return undefined
  const used = Math.max(0, Math.min(num(rec.daily_tokens_used), limit))
  return {
    name: "免费额度",
    used: (used / limit) * 100,
    display: `${formatCredit(used)} / ${formatCredit(limit)}`,
    amount: used,
    limit,
    unit: "tokens",
    aside: true,
    ...(ids.length ? { models: [...ids].sort() } : {}),
  }
}

/**
 * A credit bucket as a usage window. magpie reads its routing cap off the
 * windows it is given, so only the package total is allowed to pause the
 * account: the per-bucket breakdown is the same money seen from another angle,
 * and a bonus bucket spent on its own would otherwise stop an account that
 * still has credits elsewhere.
 */
function creditWindow(name, limit, remain) {
  const used = Math.max(0, limit - remain)
  return {
    name,
    used: limit > 0 ? Math.min(100, (used / limit) * 100) : 0,
    display: `${formatCredit(used)} / ${formatCredit(limit)}`,
    amount: used,
    limit,
    unit: "credits",
    // Only the package total may pause the account; the rest are breakdowns.
    ...(name !== TOTAL_CREDIT_LABEL ? { aside: true } : {}),
  }
}

/** Map the account's `statistics/plugin` answer to magpie's usage shape. */
function usageFromStatistics(raw, benefitRaw, benefitIds = benefitModelIds) {
  let data = raw
  if (raw && typeof raw.code === "number") {
    if (raw.code !== 0) return { error: firstOf(raw.message, raw.msg, `CodeArts code ${raw.code}`), windows: [] }
    data = asRecord(raw.data)
  }
  if (!data || typeof data !== "object") return { error: "CodeArts could not be parsed", windows: [] }
  const pkg = asRecord(data.package)
  const plan = firstOf(pkg.package_name_cn, pkg.package_name_en, pkg.spec_code)
  const metrics = Array.isArray(data.metrics) ? data.metrics : []

  const windows = []
  for (const item of metrics) {
    const rec = asRecord(item)
    const name = CREDIT_METRIC_LABELS[rec.name]
    if (!name) continue
    const limit = num(rec.package_credit_amount)
    const remain = num(rec.package_credit_remain)
    if (limit <= 0 && remain <= 0) continue // empty bucket, nothing to show
    windows.push(creditWindow(name, limit, remain))
  }

  // Keep the package total on top, then the per-bucket breakdown, then the
  // separate free-quota pool.
  windows.sort((a, b) => (a.name === TOTAL_CREDIT_LABEL ? -1 : b.name === TOTAL_CREDIT_LABEL ? 1 : 0))
  const benefit = benefitWindow(benefitRaw, benefitIds)
  if (benefit) windows.push(benefit)

  if (windows.length > 0) return { plan: plan || undefined, signIn: "kept", windows }
  return { plan: plan || undefined, windows, error: "该账号无积分额度" }
}

// ---- the plugin -------------------------------------------------------------

export const CodeArtsAuthPlugin = async ({ client } = {}, options = {}) => {
  const fetcher = typeof options?.fetch === "function" ? options.fetch : fetch
  const queueRetryDelayMs = options?.queueRetryDelayMs ?? QUEUE_RETRY_DELAY_MS
  const queueMaxAttempts = options?.queueMaxAttempts ?? QUEUE_MAX_ATTEMPTS
  const maxInflight = options?.maxInflight ?? ACCOUNT_MAX_INFLIGHT
  const gates = new Map()
  const gateFor = (key) => {
    if (!gates.has(key)) gates.set(key, createConcurrencyGate(maxInflight))
    return gates.get(key)
  }

  const configModel = (m) => ({
    name: m.name,
    limit: { context: m.context ?? 0, output: 0 },
    tool_call: true,
    // magpie's own field: the model is served from the free daily token pool,
    // not the plan's credits, so its picker row says 免费.
    ...(isBenefitModel(m.id) ? { free: true } : {}),
  })

  const modelOf = (provider, live) => {
    const base = provider.models?.[live.id] ?? {}
    return {
      ...base,
      id: live.id,
      name: live.name,
      limit: { context: live.context ?? base.limit?.context ?? 0, output: 0 },
      // Same source of truth as the signed `maas_type: benefit` header, so a
      // model never shows as free while being billed as paid, or the reverse.
      ...(live.benefit === true || isBenefitModel(live.id) ? { free: true } : {}),
    }
  }

  return {
    // The provider and the models it has before anyone is signed in.
    config: async (config) => {
      config.provider ??= {}
      config.provider[PROVIDER] ??= {}
      const p = config.provider[PROVIDER]
      p.name ??= "CodeArts"
      p.npm ??= "@ai-sdk/openai-compatible" // chat completions
      p.api ??= CHAT_API_BASE
      p.models = { ...Object.fromEntries(CATALOG.map((m) => [m.id, configModel(m)])), ...p.models }
    },

    // The account's own list when signed in and CodeArts answers.
    provider: {
      id: PROVIDER,
      async models(provider, { auth } = {}) {
        const cred = credentialOf(auth)
        if (!cred) return provider.models
        try {
          const list = await fetchRemoteModels(cred, fetcher)
          if (!list.length) return provider.models
          return Object.fromEntries(list.map((m) => [m.id, modelOf(provider, m)]))
        } catch {
          return provider.models
        }
      },
    },

    auth: {
      provider: PROVIDER,
      refreshLead: REFRESH_LEAD_MS,
      maxConcurrency: 4,

      // magpie's own hook: renew the temporary credentials before they expire.
      async refresh(auth) {
        const cred = credentialOf(auth)
        if (!cred) return undefined
        return authRecord(await refreshCredential(cred, fetcher))
      },

      // Every request the account makes is signed here.
      async loader(getAuth) {
        let cred = credentialOf(await getAuth())
        if (!cred || !cred.secret_access_key) return {}

        // Kept for hosts that ignore `auth.refresh` (OpenCode / old magpie):
        // refresh in-band when the credential is about to expire.
        let refreshing = null
        // Set when the vendor refuses the refresh for good: the one-time token is
        // spent, so only a fresh sign-in brings the account back. Every later
        // request answers 401 instead of asking the vendor again.
        let signInDead = false
        // One renewal at a time; `null` means it failed, and the caller decides
        // what that is worth (the old credential, or a 401).
        const renewCredential = () => {
          if (signInDead || !cred.refresh_token) return null
          refreshing ??= refreshCredential(cred, fetcher)
            .then((next) => {
              cred = next
              void persistCredential(client, next)
              return next
            })
            .catch((error) => {
              // Only a refresh the server refuses for good kills the account; a
              // network hiccup must not.
              if (/STS5\.1806|invalid refresh token|refresh token has been used/i.test(String(error?.message ?? error))) {
                signInDead = true
              }
              return null
            })
            .finally(() => { refreshing = null })
          return refreshing
        }

        // One account = one session id pair (a CodeArts session survives 60-90s
        // after its request and counts against the account's session budget the
        // whole time), and one gate for its request budget. The id is minted at
        // sign-in and kept across refreshes; older credentials fall back to
        // their account identifiers.
        const seed = firstOf(cred.session_id, cred.user_id, cred.user_name, cred.access_key_id)
        const context = {
          sessionId: seed,
          chatId: `chat-${seed}`,
          fetcher,
          gate: gateFor(seed),
          queueRetryDelayMs,
          queueMaxAttempts,
          renewCredential,
          signInDead: () => signInDead,
        }
        return {
          baseURL: CHAT_API_BASE,
          async fetch(input, init = {}) {
            const expiring = !signInDead && cred.refresh_token
              && Date.parse(cred.expires_at || 0) - Date.now() <= REFRESH_LEAD_MS
            const current = expiring ? (await renewCredential()) ?? cred : cred
            return signedFetch(current, input, init, context)
          },
        }
      },

      // magpie's own hook: how much of the plan is left.
      async usage(getAuth) {
        const cred = credentialOf(await getAuth())
        if (!cred) return { error: "not signed in", windows: [] }
        try {
          const text = await signedGet(SNAP_STATISTICS_URL, cred, fetcher, {
            "Agent-Type": "PromptCenter",
            "X-Language": "zh-cn",
          })
          if (text === undefined) return { error: "CodeArts answered an error", windows: [] }
          // The free-quota panel is best-effort: a credit account with no
          // benefit pool is normal, so its absence must not fail the whole read.
          const benefitText = await signedGet(BENEFIT_BALANCE_URL, cred, fetcher)
          return usageFromStatistics(safeJson(text), safeJson(benefitText ?? ""))
        } catch (e) {
          return { error: e?.message ?? String(e), windows: [] }
        }
      },

      // magpie's own hook: the account's daily check-in (签到), the 1000-credit
      // `USER_LOGIN` campaign, claimed on the IDE's signed ops route — the same
      // temporary credential the chat models use, no web session needed. When
      // that route is not offered, it reports the free-benefit enrollment.
      async checkin(getAuth) {
        const cred = credentialOf(await getAuth())
        if (!cred) return { outcome: "failed", message: "not signed in" }
        // An ops-route error falls through: the benefit report is the last word.
        return (await signedOpsCheckin(cred, fetcher).catch(() => null)) ?? benefitCheckin(cred, fetcher)
      },

      methods: [
        {
          type: "oauth",
          label: "Sign in with Huawei Cloud",
          async authorize() {
            const flow = await startOAuthFlow(fetcher)
            return {
              url: flow.loginUrl,
              instructions: "Sign in to Huawei Cloud in the browser; this window closes itself when done.",
              method: "auto",
              async callback() {
                try {
                  const cred = await flow.result
                  if (!cred?.access_key_id) return { type: "failed", error: "CodeArts did not return a credential" }
                  const accountId = firstOf(cred.user_name, cred.user_id)
                  return { type: "success", ...authRecord(cred), ...(accountId ? { accountId } : {}) }
                } catch (e) {
                  return { type: "failed", error: e?.message ?? String(e) }
                } finally {
                  await flow.close()
                }
              },
            }
          },
        },
      ],
    },
  }
}

/** Best-effort: store a freshly refreshed credential back on the account. */
async function persistCredential(client, cred) {
  try {
    await client?.auth?.set?.({ path: { id: PROVIDER }, body: { type: "oauth", ...authRecord(cred) } })
  } catch {
    /* best effort */
  }
}

// for tests (never a plugin: magpie only calls exported functions)
export const _internal = {
  CHAT_API_BASE, OPENGW_CLAIM_URL, BENEFIT_GATEWAY_CONFIG_URL, QUEUE_STATUS_URL, ACCOUNT_MAX_INFLIGHT, STS_TOKEN_ENDPOINT,
  SNAP_OPS_BASE, SNAP_OPS_DELIVERY_URL, SNAP_OPS_CLAIM_URL, SNAP_OPS_CONFIRM_URL, OPS_SIGNED_HEADERS,
  normalizeModelId, b64url, sha256Hex, hmacSha256Hex,
  generatePkcePair, generateDpopKeyPair, signDpopJws, signRequestHuawei,
  credentialFromTokenResponse, credentialOf, expiresFromCredential, refreshCredential,
  buildOAuthLoginUrl, startOAuthFlow,
  isBenefitModel, signedGet, signedCall,
  isRetryableQueueCode,
  parseSseEvents, completionFromChunks, benefitWindow, creditWindow,
  parseModelInfo, extractArray, fetchRemoteModels, usageFromStatistics,
  parseClaimReply, benefitRecord, gatewayEnabled, opsEnvelope,
}
