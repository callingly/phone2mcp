import { config, type Env } from "./env";
import { signRecord } from "./crypto";
import { PROTOCOL_VERSION, type BindingRecord } from "./protocol";

export const kvKey = (tel: string) => `tel:${tel}`;

/** What `GET /v0/lookup/{tel}` returns for a bound number. */
export interface LookupEntry {
  tel: string;
  /** Compact JWS of the binding record. Buyers must verify it. */
  record: string;
  /** Unsigned hint: when this number last moved to a different MCP URL. */
  mcp_url_changed_at?: number;
}

export interface ClaimRow {
  id: string;
  account_id: string;
  tel: string;
  mcp_url: string;
  server_key: string;
  registrant: string;
  operator: string | null;
  status: string;
  failure_reason: string | null;
  attested_at: number;
  takeover_after: number | null;
  created_at: number;
  updated_at: number;
}

export interface BindingRow {
  tel: string;
  claim_id: string;
  account_id: string;
  jti: string;
  record: string;
  mcp_url: string;
  server_key: string;
  iat: number;
  exp: number;
  verified_at: number;
  verified_until: number;
  next_reverify_at: number;
  reverify_failures: number;
  mcp_url_changed_at: number | null;
}

/** What a challenge needs to know about the claim it is verifying. */
export interface ChallengeSubject {
  id: string;
  tel: string;
  claimId: string;
  /**
   * claim: first proof of a claim. reverify: periodic re-proof of a binding.
   * takeover: the confirming second proof of a held claim (see issueBinding).
   */
  kind: "claim" | "reverify" | "takeover";
  createdAt: number;
  expiresAt: number;
}

const nowSec = () => Math.floor(Date.now() / 1000);

/** What a successful challenge produced. */
export type IssueResult =
  | { status: "bound"; entry: LookupEntry }
  | { status: "held"; takeoverAfter: number };

/** Pick a random time in the middle of a verification's life to re-challenge it. */
export function scheduleReverify(iat: number, ttl: number): number {
  const lo = 0.4 * ttl;
  const hi = 0.75 * ttl;
  return iat + Math.floor(lo + Math.random() * (hi - lo));
}

export async function lookup(env: Env, tel: string): Promise<LookupEntry | null> {
  const v = await env.RECORDS.get<Omit<LookupEntry, "tel">>(kvKey(tel), "json");
  return v ? { tel, ...v } : null;
}

export async function challengeStarted(env: Env, s: ChallengeSubject): Promise<void> {
  const stmts = [
    env.DB.prepare(
      "INSERT INTO challenges (id, claim_id, tel, kind, status, created_at, expires_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
    ).bind(s.id, s.claimId, s.tel, s.kind, Math.floor(s.createdAt / 1000), Math.floor(s.expiresAt / 1000)),
  ];
  if (s.kind !== "reverify") {
    stmts.push(
      env.DB.prepare(
        "UPDATE claims SET status = 'verifying', failure_reason = NULL, updated_at = ? WHERE id = ?",
      ).bind(nowSec(), s.claimId),
    );
  }
  await env.DB.batch(stmts);
}

function buildRecord(claim: ClaimRow, now: number, exp: number): BindingRecord {
  return {
    v: PROTOCOL_VERSION,
    tel: claim.tel,
    mcp_url: claim.mcp_url,
    server_key: claim.server_key,
    registrant: claim.registrant,
    ...(claim.operator ? { operator: claim.operator } : {}),
    verified_by: ["callback"],
    iat: now,
    exp,
    jti: crypto.randomUUID(),
  };
}

async function publish(env: Env, tel: string, jws: string, exp: number, urlChangedAt: number | null): Promise<LookupEntry> {
  const value = { record: jws, ...(urlChangedAt ? { mcp_url_changed_at: urlChangedAt } : {}) };
  await env.RECORDS.put(kvKey(tel), JSON.stringify(value), { expiration: exp });
  return { tel, ...value };
}

/**
 * A challenge succeeded. Usually this binds the number: a fresh verification
 * window starts and a short-lived record is signed and published.
 *
 * A first proof by a different account for a number that is already bound
 * does not switch it: the claim is held for TAKEOVER_HOLD_SECONDS and must
 * pass a second call-back then (kind "takeover"). A brief call-forwarding
 * hijack can't pass both, and the current binding keeps working meanwhile.
 *
 * Returns null if a re-verification raced with the binding being removed.
 */
export async function issueBinding(env: Env, s: ChallengeSubject): Promise<IssueResult | null> {
  const claim = await env.DB.prepare("SELECT * FROM claims WHERE id = ?").bind(s.claimId).first<ClaimRow>();
  if (!claim) return null;
  const existing = await env.DB.prepare("SELECT * FROM bindings WHERE tel = ?").bind(s.tel).first<BindingRow>();
  if (s.kind === "reverify" && existing?.claim_id !== s.claimId) return null;

  const { recordTtl, verificationTtl, takeoverHold } = config(env);
  const now = nowSec();

  if (s.kind === "claim" && existing && existing.account_id !== claim.account_id && takeoverHold > 0) {
    const takeoverAfter = now + takeoverHold;
    await env.DB.batch([
      env.DB.prepare("UPDATE claims SET status = 'held', takeover_after = ?, updated_at = ? WHERE id = ?").bind(takeoverAfter, now, claim.id),
      env.DB.prepare("UPDATE challenges SET status = 'succeeded', resolved_at = ? WHERE id = ?").bind(now, s.id),
    ]);
    return { status: "held", takeoverAfter };
  }

  // Write only if the binding is still what was read above (none, or the same jti).
  const guard = existing ? "WHERE bindings.jti = ?" : "WHERE 0";
  // The rest of the batch applies only if that write landed (D1 batches are transactions).
  const written = "EXISTS (SELECT 1 FROM bindings WHERE tel = ? AND jti = ?)";

  const verifiedUntil = now + verificationTtl;
  const record = buildRecord(claim, now, Math.min(now + recordTtl, verifiedUntil));
  const jws = await signRecord(env, record);

  const replacing = existing && existing.claim_id !== claim.id ? existing : null;
  const urlChangedAt = replacing && replacing.mcp_url !== claim.mcp_url ? now : (existing?.mcp_url_changed_at ?? null);

  const stmts = [
    env.DB.prepare(
      `INSERT INTO bindings (tel, claim_id, account_id, jti, record, mcp_url, server_key, iat, exp,
         verified_at, verified_until, next_reverify_at, reverify_failures, mcp_url_changed_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
       ON CONFLICT(tel) DO UPDATE SET
         claim_id = excluded.claim_id, account_id = excluded.account_id, jti = excluded.jti,
         record = excluded.record, mcp_url = excluded.mcp_url, server_key = excluded.server_key,
         iat = excluded.iat, exp = excluded.exp, verified_at = excluded.verified_at,
         verified_until = excluded.verified_until, next_reverify_at = excluded.next_reverify_at,
         reverify_failures = 0, mcp_url_changed_at = excluded.mcp_url_changed_at,
         updated_at = excluded.updated_at
       ${guard}`,
    ).bind(
      claim.tel, claim.id, claim.account_id, record.jti, jws, claim.mcp_url, claim.server_key,
      record.iat, record.exp, now, verifiedUntil, scheduleReverify(now, verificationTtl), urlChangedAt, now, now,
      ...(existing ? [existing.jti] : []),
    ),
    env.DB.prepare(`UPDATE claims SET status = 'verified', failure_reason = NULL, takeover_after = NULL, updated_at = ? WHERE id = ? AND ${written}`)
      .bind(now, claim.id, claim.tel, record.jti),
    env.DB.prepare(`UPDATE challenges SET status = 'succeeded', resolved_at = ? WHERE id = ? AND ${written}`)
      .bind(now, s.id, claim.tel, record.jti),
  ];
  if (replacing) {
    stmts.push(
      env.DB.prepare(`INSERT OR IGNORE INTO revocations (jti, tel, reason, revoked_at) SELECT ?, ?, 'superseded', ? WHERE ${written}`)
        .bind(replacing.jti, s.tel, now, claim.tel, record.jti),
      env.DB.prepare(`UPDATE claims SET status = 'superseded', updated_at = ? WHERE id = ? AND ${written}`)
        .bind(now, replacing.claim_id, claim.tel, record.jti),
    );
  }
  const [write] = await env.DB.batch(stmts);
  if (!write.meta.changes) throw new Error(`binding for ${s.tel} changed during issuance`);

  return { status: "bound", entry: await publish(env, claim.tel, jws, record.exp, urlChangedAt) };
}

/**
 * Re-sign a binding's record without a call: a new jti and a fresh short
 * `exp`, never past `verified_until`. This is what keeps records short-lived,
 * so a revoked record stops verifying within RECORD_TTL_SECONDS.
 * Runs inside the number's ChallengeDO.
 */
export async function resignBinding(env: Env, tel: string, now: number): Promise<boolean> {
  const binding = await env.DB.prepare("SELECT * FROM bindings WHERE tel = ?").bind(tel).first<BindingRow>();
  if (!binding || binding.verified_until <= now || binding.exp >= binding.verified_until) return false;
  const claim = await env.DB.prepare("SELECT * FROM claims WHERE id = ?").bind(binding.claim_id).first<ClaimRow>();
  if (!claim) return false;
  const { recordTtl } = config(env);
  const record = buildRecord(claim, now, Math.min(now + recordTtl, binding.verified_until));
  const jws = await signRecord(env, record);
  // Publish before saving the new `exp`: if the KV write fails, D1 still shows
  // the old `exp`, so the next cron run retries instead of skipping a record
  // that was never published.
  await publish(env, tel, jws, record.exp, binding.mcp_url_changed_at);
  const res = await env.DB.prepare("UPDATE bindings SET jti = ?, record = ?, iat = ?, exp = ?, updated_at = ? WHERE tel = ? AND jti = ?")
    .bind(record.jti, jws, record.iat, record.exp, now, tel, binding.jti)
    .run();
  return res.meta.changes > 0;
}

/**
 * A challenge failed. `hard` means the answering system actively gave a wrong
 * answer (evidence it is not the claimed server); `soft` covers no answer and timeouts.
 */
export async function challengeFailed(env: Env, s: ChallengeSubject, reason: string, hard: boolean): Promise<void> {
  const now = nowSec();
  // Safe to retry: the challenge row is marked last, and a retry after that is a no-op.
  const row = await env.DB.prepare("SELECT status FROM challenges WHERE id = ?").bind(s.id).first<{ status: string }>();
  if (row && row.status !== "pending") return;
  const markChallenge = env.DB.prepare("UPDATE challenges SET status = 'failed', failure_reason = ?, resolved_at = ? WHERE id = ?")
    .bind(reason, now, s.id);

  if (s.kind !== "reverify") {
    // A failed confirming call fails the held claim; the current binding is untouched.
    await env.DB.batch([
      env.DB.prepare("UPDATE claims SET status = 'failed', failure_reason = ?, updated_at = ? WHERE id = ? AND status = 'verifying'")
        .bind(reason, now, s.claimId),
      markChallenge,
    ]);
    return;
  }

  const binding = await env.DB.prepare("SELECT * FROM bindings WHERE tel = ? AND claim_id = ?")
    .bind(s.tel, s.claimId)
    .first<BindingRow>();
  if (binding) {
    const { reverifyMaxFailures, reverifyRetry } = config(env);
    const failures = binding.reverify_failures + 1;
    const nextAttempt = now + reverifyRetry;
    if (hard || failures >= reverifyMaxFailures || nextAttempt >= binding.verified_until) {
      await revokeBinding(env, s.tel, `reverify_failed:${reason}`, { jti: binding.jti });
    } else {
      await env.DB.prepare("UPDATE bindings SET reverify_failures = ?, next_reverify_at = ?, updated_at = ? WHERE tel = ? AND jti = ?")
        .bind(failures, nextAttempt, now, s.tel, binding.jti)
        .run();
    }
  }
  await markChallenge.run();
}

/**
 * Remove a binding and revoke its current record. With `accountId` or `jti`,
 * only a binding that still matches is touched. Callers run inside the
 * number's ChallengeDO, which serializes all writes to its binding and KV key.
 */
export async function revokeBinding(
  env: Env,
  tel: string,
  reason: string,
  match: { accountId?: string; jti?: string } = {},
): Promise<boolean> {
  const binding = await env.DB.prepare("SELECT * FROM bindings WHERE tel = ?").bind(tel).first<BindingRow>();
  if (!binding) return false;
  if (match.accountId !== undefined && binding.account_id !== match.accountId) return false;
  if (match.jti !== undefined && binding.jti !== match.jti) return false;
  const now = nowSec();
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO revocations (jti, tel, reason, revoked_at) VALUES (?, ?, ?, ?)").bind(binding.jti, tel, reason, now),
    env.DB.prepare("DELETE FROM bindings WHERE tel = ? AND jti = ?").bind(tel, binding.jti),
    env.DB.prepare("UPDATE claims SET status = 'revoked', failure_reason = ?, updated_at = ? WHERE id = ?").bind(reason, now, binding.claim_id),
  ]);
  await env.RECORDS.delete(kvKey(tel));
  return true;
}

/** Drop a binding whose verification ran out. Runs inside the number's ChallengeDO. */
export async function expireBinding(env: Env, tel: string, nowSec: number): Promise<boolean> {
  const binding = await env.DB.prepare("SELECT claim_id, jti FROM bindings WHERE tel = ? AND verified_until <= ?")
    .bind(tel, nowSec)
    .first<Pick<BindingRow, "claim_id" | "jti">>();
  if (!binding) return false;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM bindings WHERE tel = ? AND jti = ?").bind(tel, binding.jti),
    env.DB.prepare("UPDATE claims SET status = 'expired', updated_at = ? WHERE id = ?").bind(nowSec, binding.claim_id),
  ]);
  await env.RECORDS.delete(kvKey(tel));
  return true;
}
