import { CompactSign, importJWK, type JWK } from "jose";
import type { Env } from "./env";
import { RECORD_TYP, base64urlDecode, type BindingRecord } from "./protocol";

const enc = new TextEncoder();

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomToken(bytes = 32): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  let bin = "";
  for (const b of buf) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "")}`;
}

/** Uniformly random decimal digits, for a nonce that is easy to speak. */
export function randomDigits(n: number): string {
  let out = "";
  while (out.length < n) {
    for (const b of crypto.getRandomValues(new Uint8Array(n))) {
      if (b < 250 && out.length < n) out += String(b % 10); // reject 250..255 to avoid bias
    }
  }
  return out;
}

export function timingSafeEqual(a: string, b: string): boolean {
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

/** True if `s` is a base64url raw Ed25519 public key (32 bytes). */
export function isEd25519PublicKey(s: string): boolean {
  try {
    return base64urlDecode(s).length === 32;
  } catch {
    return false;
  }
}

export async function verifyEd25519(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}

// --- Registry signing key -------------------------------------------------

interface SigningKey {
  kid: string;
  key: CryptoKey;
  publicJwk: JWK;
}

let cached: { source: string; value: SigningKey } | undefined;

export async function signingKey(env: Env): Promise<SigningKey> {
  const source = env.REGISTRY_SIGNING_JWK;
  if (cached?.source === source) return cached.value;
  if (!source) throw new Error("REGISTRY_SIGNING_JWK is not configured");
  const jwk = JSON.parse(source) as JWK;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d || !jwk.kid) {
    throw new Error("REGISTRY_SIGNING_JWK must be a private Ed25519 JWK with a kid");
  }
  const key = (await importJWK(jwk, "EdDSA")) as CryptoKey;
  const { kty, crv, x, kid } = jwk;
  const value = { kid, key, publicJwk: { kty, crv, x, kid, alg: "EdDSA", use: "sig" } };
  cached = { source, value };
  return value;
}

/** The registry's published keys: the active key plus any retired ones. */
export async function publicJwks(env: Env): Promise<{ keys: JWK[] }> {
  const active = await signingKey(env);
  const retired: JWK[] = env.REGISTRY_RETIRED_JWKS ? JSON.parse(env.REGISTRY_RETIRED_JWKS) : [];
  const keys = [active.publicJwk, ...retired.filter((k) => k.kid !== active.kid).map(({ d: _d, ...pub }) => pub)];
  return { keys };
}

export async function signRecord(env: Env, record: BindingRecord): Promise<string> {
  const { kid, key } = await signingKey(env);
  return new CompactSign(enc.encode(JSON.stringify(record)))
    .setProtectedHeader({ alg: "EdDSA", kid, typ: RECORD_TYP })
    .sign(key);
}
