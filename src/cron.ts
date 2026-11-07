import { config, type Env } from "./env";
import type { BindingRow, ClaimRow } from "./bindings";

/** Bindings re-challenged per cron run; the rest wait for the next run. */
const REVERIFY_BATCH = 25;

/** Records re-signed per cron run. */
const RESIGN_BATCH = 200;

const stub = (env: Env, tel: string) => env.CHALLENGES.get(env.CHALLENGES.idFromName(tel));

/**
 * Runs on the cron trigger. Every write goes through the number's ChallengeDO.
 * 1. Drops bindings whose verification ran out.
 * 2. Re-signs records nearing `exp` (no call), so a revoked record dies
 *    within RECORD_TTL_SECONDS.
 * 3. Starts a call-back re-verification for bindings whose random
 *    re-verify time has come.
 * 4. Starts the confirming call-back for held takeovers whose hold is over.
 */
export async function runScheduled(
  env: Env,
  now = Date.now(),
): Promise<{ expired: number; resigned: number; started: number; takeovers: number }> {
  const nowSec = Math.floor(now / 1000);
  const { recordRefresh } = config(env);

  const expired = await env.DB.prepare("SELECT tel FROM bindings WHERE verified_until <= ? LIMIT 100")
    .bind(nowSec)
    .all<Pick<BindingRow, "tel">>();
  const dropped = await Promise.all(expired.results.map((b) => stub(env, b.tel).expire(b.tel, nowSec)));

  const stale = await env.DB.prepare(
    "SELECT tel FROM bindings WHERE exp <= ? AND exp < verified_until AND verified_until > ? ORDER BY exp LIMIT ?",
  )
    .bind(nowSec + recordRefresh, nowSec, RESIGN_BATCH)
    .all<Pick<BindingRow, "tel">>();
  const resigned = await Promise.all(stale.results.map((b) => stub(env, b.tel).resign(b.tel, nowSec)));

  const due = await env.DB.prepare(
    "SELECT tel, claim_id, server_key, mcp_url FROM bindings WHERE next_reverify_at <= ? AND verified_until > ? ORDER BY next_reverify_at LIMIT ?",
  )
    .bind(nowSec, nowSec, REVERIFY_BATCH)
    .all<Pick<BindingRow, "tel" | "claim_id" | "server_key" | "mcp_url">>();
  const started = await Promise.all(
    due.results.map((b) => stub(env, b.tel).begin({ tel: b.tel, claimId: b.claim_id, serverKey: b.server_key, mcpUrl: b.mcp_url, kind: "reverify" })),
  );

  const held = await env.DB.prepare(
    "SELECT id, tel, server_key, mcp_url FROM claims WHERE status = 'held' AND takeover_after <= ? ORDER BY takeover_after LIMIT ?",
  )
    .bind(nowSec, REVERIFY_BATCH)
    .all<Pick<ClaimRow, "id" | "tel" | "server_key" | "mcp_url">>();
  const takeovers = await Promise.all(
    held.results.map((cl) => stub(env, cl.tel).begin({ tel: cl.tel, claimId: cl.id, serverKey: cl.server_key, mcpUrl: cl.mcp_url, kind: "takeover" })),
  );

  return {
    expired: dropped.filter(Boolean).length,
    resigned: resigned.filter(Boolean).length,
    started: started.filter((r) => r.ok).length,
    takeovers: takeovers.filter((r) => r.ok).length,
  };
}
