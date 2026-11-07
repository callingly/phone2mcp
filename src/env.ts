import type { ChallengeDO } from "./challenge";

export interface Env {
  DB: D1Database;
  /** Signed records keyed by `tel:<E.164>`, read by public lookups. */
  RECORDS: KVNamespace;
  CHALLENGES: DurableObjectNamespace<ChallengeDO>;

  /** Optional Workers rate limiting bindings; skipped when absent. */
  LOOKUP_LIMITER?: RateLimit;
  BATCH_LIMITER?: RateLimit;
  CHALLENGE_LIMITER?: RateLimit;

  // --- Secrets ---
  /** Private Ed25519 JWK (with `kid`) the registry signs records with. */
  REGISTRY_SIGNING_JWK: string;
  /** Bearer token for `/v0/admin/*`. */
  ADMIN_TOKEN?: string;
  TELNYX_API_KEY?: string;
  /** base64 Ed25519 public key from the Telnyx portal, for webhook signatures. */
  TELNYX_PUBLIC_KEY?: string;

  // --- Vars ---
  /** JSON array of retired public JWKs still published for verification. */
  REGISTRY_RETIRED_JWKS?: string;
  /** Public origin of this Worker, used for Telnyx webhook URLs. */
  PUBLIC_BASE_URL?: string;
  /** "telnyx" (default) or "mock" (no calls placed; for tests and local dev). */
  TELEPHONY_PROVIDER?: string;
  TELNYX_CONNECTION_ID?: string;
  TELNYX_FROM_NUMBER?: string;
  TELNYX_VOICE?: string;
  RECORD_TTL_SECONDS?: string;
  CHALLENGE_TTL_SECONDS?: string;
  NONCE_DIGITS?: string;
  REVERIFY_MAX_FAILURES?: string;
  REVERIFY_RETRY_SECONDS?: string;
}

export function intVar(value: string | undefined, fallback: number): number {
  const n = value === undefined || value === "" ? NaN : Number(value);
  return Number.isFinite(n) ? Math.floor(n) : fallback;
}

export const config = (env: Env) => ({
  recordTtl: intVar(env.RECORD_TTL_SECONDS, 14 * 24 * 3600),
  challengeTtl: intVar(env.CHALLENGE_TTL_SECONDS, 180),
  nonceDigits: Math.min(Math.max(intVar(env.NONCE_DIGITS, 8), 6), 12),
  reverifyMaxFailures: intVar(env.REVERIFY_MAX_FAILURES, 3),
  reverifyRetry: intVar(env.REVERIFY_RETRY_SECONDS, 3600),
});
