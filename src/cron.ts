import type { Env } from "./env";
import type { BindingRow } from "./bindings";

/** Bindings re-challenged per cron run; the rest wait for the next run. */
const REVERIFY_BATCH = 25;

/**
 * Runs on the cron trigger:
 * 1. Drops bindings past `exp`, through each number's ChallengeDO.
 * 2. Starts a call-back re-verification for bindings whose random
 *    re-verify time has come.
 */
export async function runScheduled(env: Env, now = Date.now()): Promise<{ expired: number; started: number }> {
  const nowSec = Math.floor(now / 1000);

  const expired = await env.DB.prepare("SELECT tel FROM bindings WHERE exp <= ? LIMIT 100").bind(nowSec).all<Pick<BindingRow, "tel">>();
  const dropped = await Promise.all(
    expired.results.map((b) => env.CHALLENGES.get(env.CHALLENGES.idFromName(b.tel)).expire(b.tel, nowSec)),
  );

  const due = await env.DB.prepare(
    "SELECT tel, claim_id, server_key FROM bindings WHERE next_reverify_at <= ? AND exp > ? ORDER BY next_reverify_at LIMIT ?",
  )
    .bind(nowSec, nowSec, REVERIFY_BATCH)
    .all<Pick<BindingRow, "tel" | "claim_id" | "server_key">>();

  let started = 0;
  await Promise.all(
    due.results.map(async (b) => {
      const stub = env.CHALLENGES.get(env.CHALLENGES.idFromName(b.tel));
      const r = await stub.begin({ tel: b.tel, claimId: b.claim_id, serverKey: b.server_key, kind: "reverify" });
      if (r.ok) started++;
    }),
  );
  return { expired: dropped.filter(Boolean).length, started };
}
