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
  next_reverify_at: number;
  reverify_failures: number;
  mcp_url_changed_at: number | null;
}

/** What a challenge needs to know about the claim it is verifying. */
export interface ChallengeSubject {
  id: string;
  tel: string;
  claimId: string;
  kind: "claim" | "reverify";
  createdAt: number;
  expiresAt: number;
}

const nowSec = () => Math.floor(Date.now() / 1000);

/** Pick a random time in the middle of a record's life to re-challenge it. */
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
  if (s.kind === "claim") {
    stmts.push(
      env.DB.prepare(
        "UPDATE claims SET status = 'verifying', failure_reason = NULL, updated_at = ? WHERE id = ?",
      ).bind(nowSec(), s.claimId),
    );
  }
  await env.DB.batch(stmts);
}

/**
 * A challenge succeeded: sign a fresh record and publish it.
 * Returns null if a re-verification raced with the binding being removed.
 */
export async function issueBinding(env: Env, s: ChallengeSubject): Promise<LookupEntry | null> {
  const claim = await env.DB.prepare("SELECT * FROM claims WHERE id = ?").bind(s.claimId).first<ClaimRow>();
  if (!claim) return null;
  const existing = await env.DB.prepare("SELECT * FROM bindings WHERE tel = ?").bind(s.tel).first<BindingRow>();
  if (s.kind === "reverify" && existing?.claim_id !== s.claimId) return null;
  // Write only if the binding is still what was read above (none, or the same jti).
  const guard = existing ? "WHERE bindings.jti = ?" : "WHERE 0";
  // The rest of the batch applies only if that write landed (D1 batches are transactions).
  const written = "EXISTS (SELECT 1 FROM bindings WHERE tel = ? AND jti = ?)";

  const { recordTtl } = config(env);
  const now = nowSec();
  const record: BindingRecord = {
    v: PROTOCOL_VERSION,
    tel: claim.tel,
    mcp_url: claim.mcp_url,
    server_key: claim.server_key,
    registrant: claim.registrant,
    ...(claim.operator ? { operator: claim.operator } : {}),
    verified_by: ["callback"],
    iat: now,
    exp: now + recordTtl,
    jti: crypto.randomUUID(),
  };
  const jws = await signRecord(env, record);

  const replacing = existing && existing.claim_id !== claim.id ? existing : null;
  const urlChangedAt = replacing && replacing.mcp_url !== claim.mcp_url ? now : (existing?.mcp_url_changed_at ?? null);

  const stmts = [
    env.DB.prepare(
      `INSERT INTO bindings (tel, claim_id, account_id, jti, record, mcp_url, server_key, iat, exp,
         next_reverify_at, reverify_failures, mcp_url_changed_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
       ON CONFLICT(tel) DO UPDATE SET
         claim_id = excluded.claim_id, account_id = excluded.account_id, jti = excluded.jti,
         record = excluded.record, mcp_url = excluded.mcp_url, server_key = excluded.server_key,
         iat = excluded.iat, exp = excluded.exp, next_reverify_at = excluded.next_reverify_at,
         reverify_failures = 0, mcp_url_changed_at = excluded.mcp_url_changed_at,
         updated_at = excluded.updated_at
       ${guard}`,
    ).bind(
      claim.tel, claim.id, claim.account_id, record.jti, jws, claim.mcp_url, claim.server_key,
      record.iat, record.exp, scheduleReverify(record.iat, recordTtl), urlChangedAt, now, now,
      ...(existing ? [existing.jti] : []),
    ),
    env.DB.prepare(`UPDATE claims SET status = 'verified', failure_reason = NULL, updated_at = ? WHERE id = ? AND ${written}`)
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

  const entry: LookupEntry = { tel: claim.tel, record: jws, ...(urlChangedAt ? { mcp_url_changed_at: urlChangedAt } : {}) };
  const { tel: _tel, ...value } = entry;
  await env.RECORDS.put(kvKey(claim.tel), JSON.stringify(value), { expiration: record.exp });
  return entry;
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

  if (s.kind === "claim") {
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
    if (hard || failures >= reverifyMaxFailures || nextAttempt >= binding.exp) {
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

/** Drop a binding past its `exp`. Runs inside the number's ChallengeDO. */
export async function expireBinding(env: Env, tel: string, nowSec: number): Promise<boolean> {
  const binding = await env.DB.prepare("SELECT claim_id, jti FROM bindings WHERE tel = ? AND exp <= ?")
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
