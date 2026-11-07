/**
 * Wire formats shared by the registry, MCP servers and buyer agents.
 * Kept free of Workers-specific APIs so a client library can reuse it.
 */

export const PROTOCOL_VERSION = "0.1";

/** JWS `typ` header for binding records. */
export const RECORD_TYP = "phone2mcp-binding+jwt";

/** E.164: a leading +, a non-zero country code digit, at most 15 digits. */
export const E164 = /^\+[1-9]\d{6,14}$/;

export type VerificationMethod = "callback";

/** The payload of a signed binding record (spec § Binding record). */
export interface BindingRecord {
  v: typeof PROTOCOL_VERSION;
  tel: string;
  mcp_url: string;
  /** base64url raw Ed25519 public key held by the MCP server. */
  server_key: string;
  registrant: string;
  operator?: string;
  verified_by: VerificationMethod[];
  iat: number;
  exp: number;
  jti: string;
}

/**
 * The exact bytes an MCP server signs with its `server_key` to answer a
 * call-back challenge. `nonce` is the code the registry spoke on the call.
 * `mcpUrl` is the claimed MCP URL, so a signature only vouches for the URL
 * the key holder means: a claim that pairs someone's public key with a
 * different URL can't be completed with their signature.
 */
export function challengeResponseMessage(tel: string, nonce: string, mcpUrl: string): Uint8Array {
  return new TextEncoder().encode(`phone2mcp/${PROTOCOL_VERSION} challenge-response\n${tel}\n${nonce}\n${mcpUrl}`);
}

/** Body of `POST /v0/challenge-response`. */
export interface ChallengeResponseBody {
  tel: string;
  nonce: string;
  /** base64url Ed25519 signature over `challengeResponseMessage(tel, nonce, mcp_url)`. */
  signature: string;
}

export function base64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64Decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
