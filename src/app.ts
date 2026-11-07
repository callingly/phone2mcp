import { Hono, type Context, type MiddlewareHandler } from "hono";
import { z } from "zod";
import type { Env } from "./env";
import { isEd25519PublicKey, publicJwks, randomId, randomToken, sha256Hex, timingSafeEqual } from "./crypto";
import { lookup, revokeBinding, type BindingRow, type ClaimRow } from "./bindings";
import { parseTelnyxWebhook, verifyTelnyxSignature } from "./telephony";
import { E164 } from "./protocol";

interface Account {
  id: string;
  name: string;
  operator: string | null;
}

type AppEnv = { Bindings: Env; Variables: { account: Account } };
type Ctx = Context<AppEnv>;

export const MAX_BATCH = 50;

const tel = z.string().regex(E164, "must be an E.164 number like +16025550100");
const domain = z
  .string()
  .toLowerCase()
  .regex(/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, "must be a domain name");

const ClaimInput = z.object({
  tel,
  mcp_url: z
    .url({ protocol: /^https$/ })
    .max(2048),
  server_key: z.string().refine(isEd25519PublicKey, "must be a base64url raw Ed25519 public key"),
  registrant: domain,
});

const ChallengeResponseInput = z.object({
  tel,
  nonce: z.string().regex(/^\d{6,12}$/),
  signature: z.string().max(200),
});

const BatchLookupInput = z.object({ tels: z.array(tel).min(1).max(MAX_BATCH) });

const AccountInput = z.object({ name: z.string().min(1).max(200), operator: domain.optional() });

const error = (c: Ctx, status: number, code: string, details?: unknown) =>
  c.json({ error: code, ...(details ? { details } : {}) }, status as any);

async function body<T extends z.ZodType>(c: Ctx, schema: T): Promise<z.infer<T> | Response> {
  let raw: unknown;
  try {
    raw = await c.req.json();
  } catch {
    return error(c, 400, "invalid_json");
  }
  const parsed = schema.safeParse(raw);
  return parsed.success ? parsed.data : error(c, 400, "invalid_request", z.flattenError(parsed.error).fieldErrors);
}

const clientIp = (c: Ctx) => c.req.header("cf-connecting-ip") ?? "unknown";

function rateLimit(pick: (env: Env) => RateLimit | undefined): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const limiter = pick(c.env);
    if (limiter) {
      const { success } = await limiter.limit({ key: clientIp(c) });
      if (!success) return error(c, 429, "rate_limited");
    }
    await next();
  };
}

const requireAccount: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = c.req.header("authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!token) return error(c, 401, "unauthorized");
  const account = await c.env.DB.prepare("SELECT id, name, operator FROM accounts WHERE api_key_hash = ?")
    .bind(await sha256Hex(token))
    .first<Account>();
  if (!account) return error(c, 401, "unauthorized");
  c.set("account", account);
  await next();
};

const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = c.req.header("authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!c.env.ADMIN_TOKEN || !token || !timingSafeEqual(token, c.env.ADMIN_TOKEN)) return error(c, 401, "unauthorized");
  await next();
};

const claimView = (claim: ClaimRow) => ({
  id: claim.id,
  tel: claim.tel,
  mcp_url: claim.mcp_url,
  server_key: claim.server_key,
  registrant: claim.registrant,
  ...(claim.operator ? { operator: claim.operator } : {}),
  status: claim.status,
  ...(claim.failure_reason ? { failure_reason: claim.failure_reason } : {}),
  created_at: claim.created_at,
  updated_at: claim.updated_at,
});

export const app = new Hono<AppEnv>();

app.onError((err, c) => {
  console.error(err);
  return error(c, 500, "internal_error");
});
app.notFound((c) => error(c, 404, "not_found"));

app.get("/", (c) =>
  c.json({ service: "phone2mcp registry", version: "0.1", keys: "/.well-known/registry-keys" }),
);

// --- Public ----------------------------------------------------------------

app.get("/.well-known/registry-keys", async (c) => {
  c.header("Cache-Control", "public, max-age=3600");
  return c.json(await publicJwks(c.env));
});

app.get("/v0/lookup/:tel", rateLimit((e) => e.LOOKUP_LIMITER), async (c) => {
  const t = c.req.param("tel");
  if (!E164.test(t)) return error(c, 400, "invalid_tel");
  const entry = await lookup(c.env, t);
  c.header("Cache-Control", "public, max-age=60");
  return entry ? c.json(entry) : error(c, 404, "not_found");
});

app.post("/v0/lookup", rateLimit((e) => e.BATCH_LIMITER), async (c) => {
  const input = await body(c, BatchLookupInput);
  if (input instanceof Response) return input;
  const tels = [...new Set(input.tels)];
  const results = await Promise.all(tels.map(async (t) => (await lookup(c.env, t)) ?? { tel: t, record: null }));
  return c.json({ results });
});

/** Called by the MCP server with the nonce its phone agent heard. */
app.post("/v0/challenge-response", rateLimit((e) => e.CHALLENGE_LIMITER), async (c) => {
  const input = await body(c, ChallengeResponseInput);
  if (input instanceof Response) return input;
  const stub = c.env.CHALLENGES.get(c.env.CHALLENGES.idFromName(input.tel));
  const result = await stub.respond(input.nonce, input.signature);
  return result.ok ? c.json(result.binding) : error(c, result.status, result.error);
});

/** Telnyx Call Control webhooks for verification calls. */
app.post("/v0/telephony/telnyx", async (c) => {
  if (!c.env.TELNYX_PUBLIC_KEY) return error(c, 503, "telnyx_not_configured");
  const raw = await c.req.text();
  const ok = await verifyTelnyxSignature(
    c.env.TELNYX_PUBLIC_KEY,
    raw,
    c.req.header("telnyx-signature-ed25519"),
    c.req.header("telnyx-timestamp"),
  );
  if (!ok) return error(c, 401, "bad_signature");
  let parsed;
  try {
    parsed = parseTelnyxWebhook(JSON.parse(raw));
  } catch {
    return error(c, 400, "invalid_json");
  }
  if (parsed) {
    const stub = c.env.CHALLENGES.get(c.env.CHALLENGES.idFromName(parsed.state.t));
    await stub.onTelephonyEvent(parsed.state.c, parsed.event);
  }
  return c.json({ ok: true });
});

// --- Registrants -----------------------------------------------------------

app.post("/v0/claims", requireAccount, async (c) => {
  const input = await body(c, ClaimInput);
  if (input instanceof Response) return input;
  const account = c.get("account");
  const operator = account.operator && account.operator !== input.registrant ? account.operator : null;
  const now = Math.floor(Date.now() / 1000);
  const claim: ClaimRow = {
    id: randomId("clm"),
    account_id: account.id,
    tel: input.tel,
    mcp_url: input.mcp_url,
    server_key: input.server_key,
    registrant: input.registrant,
    operator,
    status: "pending",
    failure_reason: null,
    created_at: now,
    updated_at: now,
  };
  await c.env.DB.prepare(
    `INSERT INTO claims (id, account_id, tel, mcp_url, server_key, registrant, operator, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(claim.id, claim.account_id, claim.tel, claim.mcp_url, claim.server_key, claim.registrant, claim.operator, claim.status, now, now)
    .run();

  // Spec: flag a binding whose MCP URL changes.
  const current = await c.env.DB.prepare("SELECT mcp_url FROM bindings WHERE tel = ?").bind(input.tel).first<{ mcp_url: string }>();
  const warnings = current && current.mcp_url !== input.mcp_url ? ["number_already_bound_to_different_mcp_url"] : undefined;
  return c.json({ ...claimView(claim), ...(warnings ? { warnings } : {}) }, 201);
});

async function ownClaim(c: Ctx): Promise<ClaimRow | null> {
  return c.env.DB.prepare("SELECT * FROM claims WHERE id = ? AND account_id = ?")
    .bind(c.req.param("id"), c.get("account").id)
    .first<ClaimRow>();
}

app.get("/v0/claims/:id", requireAccount, async (c) => {
  const claim = await ownClaim(c);
  return claim ? c.json(claimView(claim)) : error(c, 404, "not_found");
});

app.post("/v0/claims/:id/verify", requireAccount, async (c) => {
  const claim = await ownClaim(c);
  if (!claim) return error(c, 404, "not_found");
  if (!["pending", "failed"].includes(claim.status)) return error(c, 409, "claim_not_verifiable", { status: claim.status });
  const stub = c.env.CHALLENGES.get(c.env.CHALLENGES.idFromName(claim.tel));
  const result = await stub.begin({ tel: claim.tel, claimId: claim.id, serverKey: claim.server_key, kind: "claim" });
  if (!result.ok) return error(c, result.error === "challenge_in_progress" ? 409 : 502, result.error);
  return c.json(
    { challenge_id: result.challengeId, claim_id: claim.id, status: "calling", expires_at: Math.floor(result.expiresAt / 1000) },
    202,
  );
});

app.delete("/v0/bindings/:tel", requireAccount, async (c) => {
  const t = c.req.param("tel");
  if (!E164.test(t)) return error(c, 400, "invalid_tel");
  const binding = await c.env.DB.prepare("SELECT account_id FROM bindings WHERE tel = ?").bind(t).first<Pick<BindingRow, "account_id">>();
  if (!binding || binding.account_id !== c.get("account").id) return error(c, 404, "not_found");
  await revokeBinding(c.env, t, "registrant_deleted", "revoked");
  return c.body(null, 204);
});

// --- Admin -----------------------------------------------------------------

/** Create a registrant account. The API key is shown once and stored hashed. */
app.post("/v0/admin/accounts", requireAdmin, async (c) => {
  const input = await body(c, AccountInput);
  if (input instanceof Response) return input;
  const id = randomId("acct");
  const apiKey = `p2m_${randomToken(32)}`;
  await c.env.DB.prepare("INSERT INTO accounts (id, name, operator, api_key_hash, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(id, input.name, input.operator ?? null, await sha256Hex(apiKey), Math.floor(Date.now() / 1000))
    .run();
  return c.json({ id, name: input.name, operator: input.operator ?? null, api_key: apiKey }, 201);
});
