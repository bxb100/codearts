// Unit tests for the CodeArts OAuth plugin. Run with: node --test
//
// These tests exercise the pieces magpie calls (_internal helpers) and the
// hooks the plugin returns, with the network stubbed out via `options.fetch`.

import test from "node:test"
import assert from "node:assert/strict"

import { CodeArtsAuthPlugin, _internal as x } from "./index.mjs"

const buf = (s) => new TextEncoder().encode(s)

// ---- crypto primitives -----------------------------------------------------

test("sha256Hex matches the known SHA-256 of the empty string", async () => {
  assert.equal(
    await x.sha256Hex(new Uint8Array()),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
})

test("hmacSha256Hex matches RFC 4231 test case 2", async () => {
  assert.equal(
    await x.hmacSha256Hex(buf("Jefe"), buf("what do ya want for nothing?")),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
})

test("generatePkcePair derives the S256 challenge from the verifier", async () => {
  const pkce = await x.generatePkcePair()
  assert.match(pkce.codeVerifier, /^[A-Za-z0-9_-]{64}$/)
  const expected = x.b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", buf(pkce.codeVerifier))))
  assert.equal(pkce.codeChallenge, expected)
})

test("signDpopJws produces a verifiable ES256 dpop+jwt", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const jws = await x.signDpopJws(keyPair, "POST", "https://sts.example.com/tokens")
  const [h, p, s] = jws.split(".")
  assert.equal(jws.split(".").length, 3)

  const header = JSON.parse(Buffer.from(h, "base64url").toString())
  assert.equal(header.alg, "ES256")
  assert.equal(header.typ, "dpop+jwt")
  assert.deepEqual(header.jwk, keyPair.publicKeyJwk)

  const payload = JSON.parse(Buffer.from(p, "base64url").toString())
  assert.equal(payload.htm, "POST")
  assert.equal(payload.htu, "https://sts.example.com/tokens")
  assert.equal(typeof payload.iat, "number")
  assert.equal(typeof payload.jti, "string")

  const key = await crypto.subtle.importKey(
    "jwk", keyPair.publicKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
  )
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(s, "base64url"), buf(`${h}.${p}`),
  )
  assert.ok(ok, "the DPoP signature must verify against the advertised public key")
})

// ---- SDK-HMAC-SHA256 signing -----------------------------------------------

test("buildCanonicalRequest lays out the canonical request exactly", () => {
  const headers = new Map([
    ["host", "example.com"],
    ["x-sdk-content-sha256", "H"],
    ["x-sdk-date", "D"],
    ["x-security-token", "ST"],
  ])
  const expected = [
    "GET",
    "/path/",
    "",
    "host:example.com",
    "x-sdk-content-sha256:H",
    "x-sdk-date:D",
    "x-security-token:ST",
    "",
    "host;x-sdk-content-sha256;x-sdk-date;x-security-token",
    "H",
  ].join("\n")
  assert.equal(x.buildCanonicalRequest("GET", "/path/", "", headers, "H"), expected)
})

test("signRequestHuawei signs a GET with the expected header set", async () => {
  const signed = await x.signRequestHuawei(
    "AK", "SK", "ST", "GET", "https://example.com/path", new Uint8Array(), undefined, "20260101T000000Z",
  )
  assert.equal(signed.get("x-sdk-date"), "20260101T000000Z")
  assert.equal(
    signed.get("x-sdk-content-sha256"),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert.equal(signed.get("x-security-token"), "ST")
  // GET carries no content-type.
  assert.equal(signed.has("content-type"), false)
  assert.match(
    signed.get("Authorization"),
    /^SDK-HMAC-SHA256 Access=AK,SignedHeaders=host;x-sdk-content-sha256;x-sdk-date;x-security-token,Signature=[0-9a-f]{64}$/,
  )
})

test("signRequestHuawei includes content-type and maas_type in a signed POST", async () => {
  const signed = await x.signRequestHuawei(
    "AK", "SK", "ST", "POST", "https://example.com/api/v2/chat/completions",
    buf('{"model":"glm-5.3-flash"}'), { maas_type: "benefit" }, "20260101T000000Z",
  )
  const auth = signed.get("Authorization")
  assert.match(auth, /SignedHeaders=content-type;host;maas_type;x-sdk-content-sha256;x-sdk-date;x-security-token,/)
  assert.equal(signed.get("content-type"), "application/json")
  assert.equal(signed.get("maas_type"), "benefit")
})

test("signRequestHuawei is deterministic for a fixed date stamp", async () => {
  const args = ["AK", "SK", "ST", "POST", "https://example.com/x", buf("body"), undefined, "20260101T000000Z"]
  const a = await x.signRequestHuawei(...args)
  const b = await x.signRequestHuawei(...args)
  assert.equal(a.get("Authorization"), b.get("Authorization"))
})

// ---- helpers ---------------------------------------------------------------

test("normalizeModelId strips only a trailing 4-digit date", () => {
  assert.equal(x.normalizeModelId("deepseek-v4-flash-0731"), "deepseek-v4-flash")
  assert.equal(x.normalizeModelId("glm-5.3-flash"), "glm-5.3-flash")
  assert.equal(x.normalizeModelId("GLM-5.2"), "GLM-5.2")
})

test("parseModelInfo keeps raw ids, drops vision models, dedupes, and fills context", () => {
  const seen = new Set()
  assert.equal(x.parseModelInfo({ model_id: "Qwen3-VL-235B", model_name: "Qwen3-VL-235B" }, seen), undefined)
  const a = x.parseModelInfo({ model_id: "GLM-5.2", model_name: "GLM-5.2" }, seen)
  assert.equal(a.id, "GLM-5.2")
  assert.equal(a.name, "GLM-5.2")
  assert.equal(a.context, 202752)
  // Same id twice is one row.
  assert.equal(x.parseModelInfo({ model_id: "GLM-5.2", model_name: "GLM-5.2" }, seen), undefined)
  // A dated id keeps its date: the dated and bare forms are two models.
  const b = x.parseModelInfo({ model_id: "deepseek-v4-flash-0731", model_name: "deepseek-v4-flash-0731" }, seen)
  assert.equal(b.id, "deepseek-v4-flash-0731")
  assert.equal(b.name, "deepseek-v4-flash")
  assert.equal(b.context, 1048576)
  const c = x.parseModelInfo({ model_id: "deepseek-v4-flash", model_name: "deepseek-v4-flash" }, seen)
  assert.equal(c.id, "deepseek-v4-flash")
})

test("parseModelInfo prefers the published context window over the static map", () => {
  const seen = new Set()
  const a = x.parseModelInfo({ model_id: "glm-5.3-flash", context_window: 131072, max_tokens: 8192 }, seen)
  assert.equal(a.context, 131072)
  assert.equal(a.output, 8192)
})

test("credentialOf round-trips a credential stored in the access field", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const cred = x.credentialFromTokenResponse(
    { credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R" },
    "verifier",
    keyPair,
  )
  const auth = { type: "oauth", access: JSON.stringify(cred), refresh: "R" }
  const back = x.credentialOf(auth)
  assert.equal(back.access_key_id, "AK")
  assert.equal(back.refresh_token, "R")
  assert.equal(back.code_verifier, "verifier")
  assert.deepEqual(back.dpop_private_key_jwk, keyPair.privateKeyJwk)
  assert.equal(x.credentialOf({ type: "api", key: "k" }), null)
})

test("expiresFromCredential parses the STS expiration or falls back to +1d", () => {
  assert.equal(x.expiresFromCredential({ expires_at: "2030-01-01T00:00:00Z" }), Date.parse("2030-01-01T00:00:00Z"))
  const soon = x.expiresFromCredential({})
  assert.ok(soon > Date.now() + 86_000_000 && soon <= Date.now() + 86_400_000)
})

test("buildOAuthLoginUrl matches the real IDE parameters", () => {
  const url = new URL(x.buildOAuthLoginUrl(12345, { codeChallenge: "CH" }, "TICKET"))
  assert.equal(url.origin + url.pathname, "https://codearts.huaweicloud.com/portal/authorize")
  const q = url.searchParams
  assert.equal(q.get("client_id"), "codearts-agent")
  assert.equal(q.get("uri_scheme"), "codearts-agent")
  assert.equal(q.get("port"), "12345")
  assert.equal(q.get("code_challenge"), "CH")
  assert.equal(q.get("code_challenge_method"), "SHA-256")
  assert.equal(q.get("ticket_id"), "TICKET")
  assert.equal(q.get("plugin-name"), "snap_AIIDE")
  // The real plugin never sends auth_callback_url (portal derives it from port).
  assert.equal(q.has("auth_callback_url"), false)
})

test("usageFromStatistics maps credit metrics to windows with real numbers", () => {
  const usage = x.usageFromStatistics({
    package: { package_name_cn: "企业版" },
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 250, package_credit_used: 750 },
      { name: "usageBasicPackageCredit", package_credit_amount: 1000, package_credit_remain: 250, package_credit_used: 750 },
      { name: "usageOnDemandPackageCredit", package_credit_amount: 20000, package_credit_remain: 20000 },
    ],
  }, { result: { daily_token_limit: 10000000, daily_tokens_used: 2500000 } }, ["glm-5.3-flash", "deepseek-v4.1-flash"])
  assert.equal(usage.plan, "企业版")
  assert.equal(usage.signIn, "kept")
  // The package total is listed first, then the buckets, all with display numbers.
  assert.deepEqual(usage.windows, [
    { name: "总积分", used: 75, display: "750 / 1000", amount: 750, limit: 1000, unit: "credits" },
    { name: "基础积分包", used: 75, display: "750 / 1000", amount: 750, limit: 1000, unit: "credits", aside: true },
    { name: "按需积分包", used: 0, display: "0 / 2.0万", amount: 0, limit: 20000, unit: "credits", aside: true },
    { name: "免费额度", used: 25, display: "250.0万 / 1000.0万", amount: 2500000, limit: 10000000, unit: "tokens", aside: true, models: ["deepseek-v4.1-flash", "glm-5.3-flash"] },
  ])
})

test("only the package total window is left out of routing", () => {
  // magpie reads its per-account cap off the windows, so a bucket other than the
  // total must never pause an account that still has credits elsewhere.
  assert.equal("aside" in x.creditWindow("总积分", 1000, 0), false)
  assert.equal(x.creditWindow("赠送积分包", 1000, 0).aside, true)
  assert.equal(x.benefitWindow({ daily_token_limit: 10, daily_tokens_used: 10 }).aside, true)
})

test("usageFromStatistics omits the free-quota window without a benefit pool", () => {
  const stats = {
    metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 250, package_credit_used: 750 }],
  }
  assert.equal(x.usageFromStatistics(stats).windows.length, 1)
  // A zero daily limit means the account has no benefit pool at all.
  const noPool = { result: { daily_token_limit: 0, daily_tokens_used: 0 } }
  assert.equal(x.usageFromStatistics(stats, noPool).windows.length, 1)
})

test("usageFromStatistics clamps a free-quota reading the endpoint over-reports", () => {
  const w = x.benefitWindow({ result: { daily_token_limit: 100, daily_tokens_used: 400 } })
  assert.deepEqual(
    { used: w.used, amount: w.amount, unit: w.unit },
    { used: 100, amount: 100, unit: "tokens" },
  )
})

test("usageFromStatistics reports no credit plan when every bucket is empty", () => {
  const usage = x.usageFromStatistics({
    metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 0, package_credit_remain: 0 }],
  })
  assert.deepEqual(usage.windows, [])
  assert.equal(usage.error, "该账号无积分额度")
})

test("usageFromStatistics surfaces a business error code", () => {
  const usage = x.usageFromStatistics({ code: 500, message: "boom" })
  assert.equal(usage.error, "boom")
})

test("toBytes normalizes strings and views", async () => {
  assert.deepEqual(await x.toBytes("hi"), buf("hi"))
  assert.deepEqual(await x.toBytes(buf("hi")), buf("hi"))
  assert.equal((await x.toBytes(null)).length, 0)
})

test("isBenefitModel honours the static fallback", () => {
  assert.equal(x.isBenefitModel("glm-5.3-flash"), true)
  assert.equal(x.isBenefitModel("GLM-5.2"), false)
})

// ---- remote model list -----------------------------------------------------

const gatewayBody = JSON.stringify({
  result: {
    models: [
      { model_id: "glm-5.3-flash", model_name: "glm-5.3-flash" },
      { model_id: "deepseek-v4-flash-0731", model_name: "deepseek-v4-flash-0731" },
      { model_id: "Qwen3-VL-235B", model_name: "Qwen3-VL-235B" },
    ],
  },
})
const builtinBody = JSON.stringify({ builtinModels: [{ model_id: "GLM-5.2", model_name: "GLM-5.2" }] })

function modelsFetcher(seen) {
  return async (url, init) => {
    seen.push({ url: String(url), auth: new Headers(init?.headers).get("authorization") })
    const body = String(url).includes("opengw") ? gatewayBody : builtinBody
    return new Response(body, { status: 200 })
  }
}

test("fetchRemoteModels merges both endpoints and keeps the published ids", async () => {
  const seen = []
  const models = await x.fetchRemoteModels(
    { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" },
    modelsFetcher(seen),
  )
  const ids = models.map((m) => m.id)
  assert.deepEqual(ids, ["glm-5.3-flash", "deepseek-v4-flash-0731", "GLM-5.2"])
  assert.ok(seen.every((s) => String(s.auth).startsWith("SDK-HMAC-SHA256")))
})

test("fetchRemoteModels marks every gateway id as benefit, dated ones included", async () => {
  const models = await x.fetchRemoteModels(
    { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" },
    modelsFetcher([]),
  )
  const byId = Object.fromEntries(models.map((m) => [m.id, m]))
  assert.equal(byId["glm-5.3-flash"].benefit, true)
  assert.equal(byId["deepseek-v4-flash-0731"].benefit, true)
  assert.equal("benefit" in byId["GLM-5.2"], false)
  // The signature is what makes a gateway id callable at all, so the set the
  // plugin signs with must be exactly the set it publishes.
  for (const m of models) if (m.benefit) assert.equal(x.isBenefitModel(m.id), true, m.id)
})

test("signedGet returns undefined on a non-2xx response", async () => {
  const fetcher = async () => new Response("nope", { status: 401 })
  const text = await x.signedGet("https://example.com/x", { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, fetcher)
  assert.equal(text, undefined)
})

// ---- plugin hooks ----------------------------------------------------------

function makeAuth(cred) {
  return { type: "oauth", access: JSON.stringify(cred), refresh: cred.refresh_token, expires: x.expiresFromCredential(cred) }
}

async function makeCred() {
  const keyPair = await x.generateDpopKeyPair()
  return x.credentialFromTokenResponse(
    { credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R" },
    "verifier",
    keyPair,
  )
}

test("plugin exposes config, provider.models, and an oauth auth method", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  assert.equal(typeof plugin.config, "function")
  assert.equal(plugin.provider.id, "codearts")
  assert.equal(plugin.auth.provider, "codearts")
  assert.equal(plugin.auth.methods.length, 1)
  assert.equal(plugin.auth.methods[0].type, "oauth")

  const config = {}
  await plugin.config(config)
  const p = config.provider.codearts
  assert.equal(p.npm, "@ai-sdk/openai-compatible")
  assert.equal(p.api, x.CHAT_API_BASE)
  assert.ok(p.models["GLM-5.2"])
})

test("loader signs each chat request with SDK-HMAC-SHA256", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push({ url: String(url), init })
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  assert.equal(loaded.baseURL, x.CHAT_API_BASE)

  await loaded.fetch("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "GLM-5.2", messages: [] }),
  })

  const headers = new Headers(seen[0].init.headers)
  assert.match(headers.get("authorization"), /^SDK-HMAC-SHA256 Access=AK,/)
  assert.equal(headers.get("lang"), "en")
  assert.ok(headers.get("chat-id"))
  assert.ok(headers.get("session-id"))
  assert.equal(headers.has("maas_type"), false)
  // Sign the rewritten body, including reasoning separation and metered streaming.
  const body = new TextDecoder().decode(seen[0].init.body)
  assert.deepEqual(JSON.parse(body), { model: "GLM-5.2", messages: [], thinking: { type: "enabled" }, stream: true })
  assert.equal(headers.get("x-sdk-content-sha256"), await x.sha256Hex(buf(body)))
})

test("loader adds a signed maas_type header for benefit models", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push(init)
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await loaded.fetch("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "glm-5.3-flash" }),
  })
  const headers = new Headers(seen[0].headers)
  assert.equal(headers.get("maas_type"), "benefit")
  assert.match(headers.get("authorization"), /SignedHeaders=[^,]*,/)
  assert.ok(headers.get("authorization").split("SignedHeaders=")[1].split(",")[0].includes("maas_type"))
})

for (const bodyType of ["string", "bytes", "request"]) {
  test(`loader normalizes chat payloads from ${bodyType} bodies before signing`, async () => {
    const cred = await makeCred()
    const seen = []
    const plugin = await CodeArtsAuthPlugin({}, { fetch: async (url, init) => {
      seen.push(init)
      return new Response("ok")
    } })
    const loaded = await plugin.auth.loader(async () => makeAuth(cred))
    const body = JSON.stringify({
      model: "codearts/glm-5.3-flash",
      messages: [],
      max_completion_tokens: 100_000,
      max_tokens: 100_000,
    })
    if (bodyType === "request") {
      await loaded.fetch(new Request(x.CHAT_API_BASE, { method: "POST", body }))
    } else {
      await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: bodyType === "bytes" ? buf(body) : body })
    }
    assert.deepEqual(JSON.parse(new TextDecoder().decode(seen[0].body)), {
      model: "glm-5.3-flash",
      messages: [],
      max_completion_tokens: 65_536,
      max_tokens: 65_536,
      thinking: { type: "enabled" },
      stream: true,
    })
    const headers = new Headers(seen[0].headers)
    assert.equal(headers.get("maas_type"), "benefit")
    assert.ok(headers.get("authorization").split("SignedHeaders=")[1].split(",")[0].includes("maas_type"))
    assert.equal(headers.get("x-sdk-content-sha256"), await x.sha256Hex(seen[0].body))
  })
}

test("loader preserves explicit thinking and valid output budgets", async () => {
  const cred = await makeCred()
  const seen = []
  const plugin = await CodeArtsAuthPlugin({}, { fetch: async (url, init) => {
    seen.push(init)
    return new Response("ok")
  } })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const body = { model: "GLM-5.2", messages: [], stream: true, thinking: { type: "disabled" }, max_tokens: 1024 }
  await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: JSON.stringify(body) })
  assert.deepEqual(JSON.parse(new TextDecoder().decode(seen[0].body)), body)
})

test("loader returns nothing when not signed in", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  assert.deepEqual(await plugin.auth.loader(async () => ({ type: "api", key: "k" })), {})
})

test("auth.refresh exchanges the refresh token for fresh credentials", async () => {
  const cred = await makeCred()
  const fetcher = async (url, init) => {
    assert.equal(String(url), x.STS_TOKEN_ENDPOINT)
    assert.equal(init.method, "POST")
    assert.ok(new Headers(init.headers).get("dpop"))
    return new Response(JSON.stringify({
      credentials: { access_key_id: "AK2", secret_access_key: "SK2", security_token: "ST2", expiration: "2031-01-01T00:00:00Z" },
      refresh_token: "R2",
    }), { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const next = await plugin.auth.refresh(makeAuth(cred))
  const parsed = JSON.parse(next.access)
  assert.equal(parsed.access_key_id, "AK2")
  assert.equal(next.refresh, "R2")
  assert.equal(next.expires, Date.parse("2031-01-01T00:00:00Z"))
})

test("provider.models returns the account's live list", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: modelsFetcher([]) })
  const provider = { models: { "GLM-5.2": { name: "GLM-5.2", limit: { context: 0, output: 0 } } } }
  const models = await plugin.provider.models(provider, { auth: makeAuth(cred) })
  assert.deepEqual(Object.keys(models).sort(), ["GLM-5.2", "deepseek-v4-flash-0731", "glm-5.3-flash"])
  assert.equal(models["GLM-5.2"].limit.context, 202752)
  // Both gateway models show as free; the builtin one carries no free marking.
  assert.equal(models["glm-5.3-flash"].free, true)
  assert.equal(models["deepseek-v4-flash-0731"].free, true)
  assert.equal("free" in models["GLM-5.2"], false)
})

test("config offers the free models under the ids the benefit header accepts", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  const config = {}
  await plugin.config(config)
  const m = config.provider.codearts.models
  // Every published free id is one isBenefitModel signs for, so the picker row
  // and the signed header can never disagree.
  for (const id of ["glm-5.3-flash", "deepseek-v4.1-flash", "deepseek-v4-flash-0731", "deepseek-v4-pro-0813"]) {
    assert.equal(m[id]?.free, true, id)
    assert.equal(x.isBenefitModel(id), true, id)
  }
  assert.equal("free" in m["GLM-5.2"], false)
  // The paid models keep their bare ids; the dated ones are the free entries.
  assert.equal("deepseek-v4-flash" in m, false)
  assert.equal("deepseek-v4-pro" in m, false)
})

test("provider.models falls back to the catalog when unsigned", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  const provider = { models: { "GLM-5.2": {} } }
  assert.deepEqual(await plugin.provider.models(provider, {}), provider.models)
})

test("auth.usage reports the plan's credit window", async () => {
  const cred = await makeCred()
  const fetcher = async (url) => {
    assert.ok(String(url).endsWith("/snap-manager/v1/statistics/plugin"))
    return new Response(JSON.stringify({
      package: { package_name_cn: "企业版" },
      metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 400 }],
    }), { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  assert.equal(usage.plan, "企业版")
  assert.deepEqual(usage.windows, [
    { name: "总积分", used: 60, display: "600 / 1000", amount: 600, limit: 1000, unit: "credits" },
  ])
})

// ---- OAuth callback server -------------------------------------------------

test("startOAuthFlow serves a callback server and a valid login URL", async () => {
  const flow = await x.startOAuthFlow(async () => new Response("", { status: 200 }))
  const url = new URL(flow.loginUrl)
  assert.equal(url.origin + url.pathname, "https://codearts.huaweicloud.com/portal/authorize")
  const port = Number(url.searchParams.get("port"))
  assert.ok(port >= 10000, "callback port must be >= 10000")

  // A callback without code/secret is rejected.
  const res = await fetch(`http://127.0.0.1:${port}/oauth/callback`)
  assert.equal(res.status, 400)

  await flow.close()
})

// ---- upstream concurrency & queueing ---------------------------------------

/** A `queue/status` answer in the shape CodeArts sends it. */
const queueStatus = (status, extra = {}) => new Response(JSON.stringify({ status, ...extra }), { status: 200 })

const isQueueUrl = (url) => String(url).startsWith(x.QUEUE_STATUS_URL)

const chatBody = (model) => JSON.stringify({ model, messages: [] })

test("isQueueErrorResponse only accepts 400 with TM.00001041", () => {
  assert.equal(x.isQueueErrorResponse(400, '{"error_code":"TM.00001041"}'), true)
  assert.equal(x.isQueueErrorResponse(400, '{"error_code":"TM.00001042"}'), false)
  assert.equal(x.isQueueErrorResponse(500, "TM.00001041"), false)
})

test("signedFetch retries TM.00001041 until upstream frees a session", async () => {
  const cred = await makeCred()
  const calls = []
  const fetcher = async (url) => {
    calls.push(String(url))
    if (isQueueUrl(url)) return queueStatus("waiting", { queue_position: 2 })
    if (calls.filter((u) => !isQueueUrl(u)).length === 1) {
      return new Response(JSON.stringify({
        error_code: "TM.00001041",
        error_msg: "并发会话数已达上限(3个)，请关闭部分会话后重试。",
      }), { status: 400 })
    }
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 200)
  assert.equal(await res.text(), "ok")
  assert.equal(calls.filter((u) => !isQueueUrl(u)).length, 2)
  assert.ok(calls.some(isQueueUrl), "the status endpoint must be polled while waiting")
})

test("signedFetch returns the last upstream answer when the queue never clears", async () => {
  const cred = await makeCred()
  let chatCalls = 0
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("waiting")
    chatCalls += 1
    return new Response('{"error_code":"TM.00001041"}', { status: 400 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1, queueMaxAttempts: 2 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 400)
  assert.match(await res.text(), /TM\.00001041/)
  assert.equal(chatCalls, 3, "one attempt plus queueMaxAttempts retries")
})

test("signedFetch stops retrying on a terminal queue status", async () => {
  const cred = await makeCred()
  let chatCalls = 0
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("queue_full", { message: "queue is full" })
    chatCalls += 1
    return new Response('{"error_code":"TM.00001041"}', { status: 400 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 400)
  assert.equal(chatCalls, 1)
})

test("signedFetch waits on a non-TM error when the status endpoint says waiting", async () => {
  const cred = await makeCred()
  let chatCalls = 0
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("waiting")
    chatCalls += 1
    if (chatCalls === 1) return new Response('{"error_code":"InferHub.ModelArts.81111.429"}', { status: 400 })
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("openpangu-2.0-flash") })
  assert.equal(res.status, 200)
  assert.equal(chatCalls, 2)
})

test("signedFetch gives up as soon as the caller aborts", async () => {
  const cred = await makeCred()
  const controller = new AbortController()
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("waiting")
    controller.abort()
    return new Response('{"error_code":"TM.00001041"}', { status: 400 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 60_000 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await assert.rejects(
    loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2"), signal: controller.signal }),
    (error) => error.name === "AbortError",
  )
})

test("the account gate never lets more than three requests in flight", async () => {
  const cred = await makeCred()
  let inFlight = 0
  let peak = 0
  const fetcher = async () => {
    inFlight += 1
    peak = Math.max(peak, inFlight)
    await new Promise((resolve) => setTimeout(resolve, 10))
    inFlight -= 1
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const call = () => loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  await Promise.all(Array.from({ length: 8 }, call))
  assert.equal(peak, x.ACCOUNT_MAX_INFLIGHT)
})

test("session and chat ids stay stable for one account", async () => {
  const cred = await makeCred()
  const headersOf = async (auth) => {
    let captured = null
    const fetcher = async (_url, init) => {
      captured = new Headers(init.headers)
      return new Response("ok", { status: 200 })
    }
    const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
    const loaded = await plugin.auth.loader(async () => auth)
    await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
    return captured
  }

  const first = await headersOf(makeAuth(cred))
  // A loader re-run for the same credential keeps the same session.
  const again = await headersOf(makeAuth(cred))
  assert.equal(first.get("session-id"), again.get("session-id"))
  assert.equal(first.get("chat-id"), again.get("chat-id"))
  // The AK rotates on refresh; the stored session id does not.
  const rotated = await headersOf(makeAuth({ ...cred, access_key_id: "AK3" }))
  assert.equal(first.get("session-id"), rotated.get("session-id"))

  const other = await headersOf(makeAuth({ ...cred, session_id: "b".repeat(32) }))
  assert.notEqual(first.get("session-id"), other.get("session-id"))
})

test("sign-in mints a session id and refresh keeps it", async () => {
  const cred = await makeCred()
  assert.match(cred.session_id, /^[0-9a-f]{32}$/)
  const fetcher = async () => new Response(JSON.stringify({
    credentials: { access_key_id: "AK9", secret_access_key: "SK9", security_token: "ST9", expiration: "2031-01-01T00:00:00Z" },
  }), { status: 200 })
  const next = await x.refreshCredential(cred, fetcher)
  assert.equal(next.access_key_id, "AK9")
  assert.equal(next.session_id, cred.session_id)
})

// ---- streaming metering ----------------------------------------------------

test("needsStreamMetering only rewrites a chat body the caller asked as JSON", () => {
  assert.equal(x.needsStreamMetering({ model: "GLM-5.2", messages: [] }), true)
  // Already streaming: upstream meters it, leave the caller's stream alone.
  assert.equal(x.needsStreamMetering({ model: "GLM-5.2", messages: [], stream: true }), false)
  assert.equal(x.needsStreamMetering({ model: "GLM-5.2" }), false)
  assert.equal(x.needsStreamMetering({ messages: [] }), false)
  assert.equal(x.needsStreamMetering(null), false)
})

test("completionFromChunks folds deltas, tool-call fragments, and usage", () => {
  const events = [
    { id: "c1", created: 111, model: "GLM-5.2", choices: [{ index: 0, delta: { role: "assistant", content: "he" } }] },
    { model: "GLM-5.2", choices: [{ index: 0, delta: { content: "llo", reasoning_content: "think", tool_calls: [{ index: 0, id: "call1", function: { name: "read", arguments: '{"a"' } }] } }] },
    { model: "GLM-5.2", choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: ':1}' } }] }, finish_reason: "tool_calls" }] },
    { model: "GLM-5.2", choices: [], usage: { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 } },
  ]
  const done = x.completionFromChunks(events)
  assert.equal(done.id, "c1")
  assert.equal(done.object, "chat.completion")
  assert.equal(done.created, 111)
  assert.equal(done.model, "GLM-5.2")
  assert.deepEqual(done.usage, { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 })
  const msg = done.choices[0].message
  assert.equal(msg.content, "hello")
  assert.equal(msg.reasoning_content, "think")
  assert.equal(done.choices[0].finish_reason, "tool_calls")
  assert.deepEqual(msg.tool_calls, [{ id: "call1", type: "function", function: { name: "read", arguments: '{"a":1}' } }])
})

test("a non-streaming caller gets JSON back from the metered stream", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push(init)
    return new Response(
      [
        sseEvent({ id: "c1", created: 5, model: "GLM-5.2", choices: [{ index: 0, delta: { role: "assistant", content: "hi" } }] }),
        sseEvent({ model: "GLM-5.2", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
        sseEvent({ model: "GLM-5.2", choices: [], usage: { prompt_tokens: 7, completion_tokens: 2, total_tokens: 9 } }),
        "data: [DONE]\n\n",
      ].join(""),
      { status: 200, headers: { "content-type": "text/event-stream" } },
    )
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 200)
  assert.match(res.headers.get("content-type"), /application\/json/)
  const done = JSON.parse(await res.text())
  assert.equal(done.choices[0].message.content, "hi")
  assert.equal(done.usage.total_tokens, 9)
  assert.equal(JSON.parse(new TextDecoder().decode(seen[0].body)).stream, true)
})

test("a caller that asked for stream: true keeps the SSE stream untouched", async () => {
  const cred = await makeCred()
  const raw = sseEvent({ model: "GLM-5.2", choices: [{ index: 0, delta: { content: "tok" } }] })
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => new Response(raw, { status: 200, headers: { "content-type": "text/event-stream" } }) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: JSON.stringify({ model: "GLM-5.2", messages: [], stream: true }) })
  assert.equal(await res.text(), raw)
})

test("an error carried by the metered stream is passed through, not folded", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => new Response(sseEvent({ error_code: "InferHub.4291.200", error_msg: "insufficient quota" }), { status: 200, headers: { "content-type": "text/event-stream" } }) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.match(await res.text(), /4291/)
})

test("parseSseEvents tolerates CRLF framing and junk lines", () => {
  const events = x.parseSseEvents('data: {"a":1}\r\n\r\ncomment\r\n:\r\ndata: {"b":2}\r\n\r\ndata: [DONE]\r\n\r\n')
  assert.deepEqual(events, [{ a: 1 }, { b: 2 }])
})

// ---- vision models & SSE-embedded queue errors -----------------------------

/** The shape CodeArts uses for a queue error inside a 200 SSE stream. */
const sseEvent = (payload) => `data: ${JSON.stringify(payload)}\n\n`

test("parseModelInfo drops vision models whatever the case", () => {
  const seen = new Set()
  assert.equal(x.parseModelInfo({ model_id: "kimi-k2.6-vl" }, seen), undefined)
  assert.equal(x.parseModelInfo({ model_id: "glm-5.2-vl-0731" }, seen), undefined)
  assert.equal(x.parseModelInfo({ model_id: "GLM-5.2" }, seen).id, "GLM-5.2")
})

test("isRetryableQueueCode treats an exhausted quota as final", () => {
  assert.equal(x.isRetryableQueueCode('{"error_code":"TM.00001041"}'), true)
  assert.equal(x.isRetryableQueueCode('{"error_code":"InferHub.ModelArts.81111.429"}'), true)
  assert.equal(x.isRetryableQueueCode("429 Too Many Requests"), true)
  // `4291` is the quota code; its `429` prefix must not be read as a rate limit.
  assert.equal(x.isRetryableQueueCode('{"error_code":"InferHub.4291.200"}'), false)
})

test("signedFetch retries a queue error embedded in a 200 SSE stream", async () => {
  const cred = await makeCred()
  let chatCalls = 0
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("waiting", { queue_position: 1 })
    chatCalls += 1
    if (chatCalls === 1) {
      return new Response(
        sseEvent({ text: "[DONE]", error_code: "InferHub.ModelArts.81111.429", error_msg: "TPM limit" }),
        { status: 200, headers: { "content-type": "text/event-stream" } },
      )
    }
    return new Response(sseEvent({ ok: true }), { status: 200, headers: { "content-type": "text/event-stream" } })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 200)
  assert.match(await res.text(), /"ok":true/)
  assert.equal(chatCalls, 2)
})

test("signedFetch answers an exhausted quota with a 429 so magpie moves accounts", async () => {
  const cred = await makeCred()
  let chatCalls = 0
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("waiting")
    chatCalls += 1
    return new Response(
      sseEvent({ error_code: "InferHub.4291.200", error_msg: "insufficient quota" }),
      { status: 200, headers: { "content-type": "text/event-stream" } },
    )
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("deepseek-v4.1-flash") })
  // A 200 would be handed over as an answer and the caller would see the stream
  // stop without a finish_reason. 429 is the shape magpie fails over on.
  assert.equal(res.status, 429)
  assert.match(await res.text(), /4291/)
  assert.equal(chatCalls, 1)
})

test("signedFetch answers a non-quota terminal SSE error with a 502", async () => {
  const cred = await makeCred()
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("waiting")
    return new Response(
      sseEvent({ error_code: "InferHub.5001.500", error_msg: "upstream broke off" }),
      { status: 200, headers: { "content-type": "text/event-stream" } },
    )
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("deepseek-v4.1-flash") })
  assert.equal(res.status, 502)
  assert.match(await res.text(), /5001/)
})

test("signedFetch still passes a stream that opens with an empty delta and then answers", async () => {
  const cred = await makeCred()
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("idle")
    // The error-capable peek must not wait past real content: a role-only delta
    // is not content, the text that follows it is.
    const body = [
      sseEvent({ choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] }),
      sseEvent({ choices: [{ index: 0, delta: { content: "hi" }, finish_reason: null }] }),
      sseEvent({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
    ].join("\n\n")
    return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 200)
  const text = await res.text()
  assert.match(text, /"hi"/)
  assert.match(text, /finish_reason/)
})

test("signedFetch renews the credential on APIG.0602 and sends the request again", async () => {
  const cred = await makeCred()
  let chatCalls = 0
  let tokenCalls = 0
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("idle")
    if (String(url).includes("oauth2/tokens")) {
      tokenCalls += 1
      return new Response(
        JSON.stringify({ credentials: { access_key_id: "AK2", secret_access_key: "SK2", security_token: "ST2", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R2" }),
        { status: 200 },
      )
    }
    chatCalls += 1
    if (chatCalls === 1) {
      return new Response(
        JSON.stringify({ error_msg: "Bad request: the security token has expired", error_code: "APIG.0602" }),
        { status: 400, headers: { "content-type": "application/json" } },
      )
    }
    return new Response(sseEvent({ choices: [{ index: 0, delta: { content: "ok" }, finish_reason: "stop" }] }),
      { status: 200, headers: { "content-type": "text/event-stream" } })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 200)
  assert.match(await res.text(), /"ok"/)
  assert.equal(tokenCalls, 1)
  assert.equal(chatCalls, 2)
})

test("signedFetch marks the account when the credential cannot be renewed", async () => {
  const cred = await makeCred()
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("idle")
    if (String(url).includes("oauth2/tokens")) {
      return new Response(
        JSON.stringify({ error_code: "STS5.1806", error_msg: "invalid refresh token: 'the refresh token has been used'" }),
        { status: 400 },
      )
    }
    return new Response(
      JSON.stringify({ error_msg: "Bad request: the security token has expired", error_code: "APIG.0602" }),
      { status: 400, headers: { "content-type": "application/json" } },
    )
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  // A bare 400 is "an error another account wouldn't fix", so magpie never
  // switches. The header is what makes it move on.
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 401)
  assert.equal(res.headers.get("X-Magpie-Sign-In"), "expired")
})

test("signedFetch fails when a queue error never clears in the stream", async () => {
  const cred = await makeCred()
  let chatCalls = 0
  const fetcher = async (url) => {
    if (isQueueUrl(url)) return queueStatus("waiting")
    chatCalls += 1
    return new Response(
      sseEvent({ error_code: "TM.00001041", error_msg: "并发会话数已达上限(3个)" }),
      { status: 200, headers: { "content-type": "text/event-stream" } },
    )
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueRetryDelayMs: 1, queueMaxAttempts: 1 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await assert.rejects(
    loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") }),
    /queue wait timed out/,
  )
  assert.equal(chatCalls, 2)
})

test("signedFetch delivers a plain 200 body unchanged", async () => {
  const cred = await makeCred()
  const fetcher = async () => new Response("plain body", { status: 200 })
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(x.CHAT_API_BASE, { method: "POST", body: chatBody("GLM-5.2") })
  assert.equal(res.status, 200)
  assert.equal(await res.text(), "plain body")
})
