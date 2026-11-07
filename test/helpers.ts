import { SELF, env } from "cloudflare:test";
import { base64urlEncode, challengeResponseMessage } from "../src/protocol";

export const BASE = "https://registry.test";

let counter = 0;
/** A unique test number per call, so tests never share a ChallengeDO. */
export function freshTel(): string {
  counter += 1;
  return `+1602555${String(1000 + counter).padStart(4, "0")}${Math.floor(Math.random() * 10)}`;
}

export async function api(method: string, path: string, opts: { token?: string; json?: unknown; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts.json !== undefined) headers["content-type"] = "application/json";
  const res = await SELF.fetch(`${BASE}${path}`, {
    method,
    headers,
    body: opts.json === undefined ? undefined : JSON.stringify(opts.json),
  });
  const text = await res.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: res.status, body, headers: res.headers };
}

export async function createAccount(operator = "callingly.com") {
  const res = await api("POST", "/v0/admin/accounts", {
    token: env.ADMIN_TOKEN,
    json: { name: `acct-${Math.random()}`, operator },
  });
  if (res.status !== 201) throw new Error(`createAccount: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body as { id: string; api_key: string };
}

export interface ServerKey {
  publicKey: string;
  sign(tel: string, nonce: string): Promise<string>;
}

/** An MCP server's key pair. */
export async function serverKey(): Promise<ServerKey> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  return {
    publicKey: base64urlEncode(raw),
    async sign(tel, nonce) {
      const sig = await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, challengeResponseMessage(tel, nonce));
      return base64urlEncode(new Uint8Array(sig));
    },
  };
}

export function challengeStub(tel: string) {
  return env.CHALLENGES.get(env.CHALLENGES.idFromName(tel));
}

export async function liveNonce(tel: string): Promise<string> {
  const s = await challengeStub(tel).inspect();
  if (!s) throw new Error(`no live challenge for ${tel}`);
  return s.nonce;
}

/** Claim a number and complete the call-back challenge. */
export async function bindNumber(opts: { token: string; key?: ServerKey; tel?: string; mcp_url?: string; registrant?: string }) {
  const key = opts.key ?? (await serverKey());
  const tel = opts.tel ?? freshTel();
  const claim = await api("POST", "/v0/claims", {
    token: opts.token,
    json: {
      tel,
      mcp_url: opts.mcp_url ?? "https://mcp.acmeplumbing.com/mcp",
      server_key: key.publicKey,
      registrant: opts.registrant ?? "acmeplumbing.com",
      attest_control: true,
    },
  });
  if (claim.status !== 201) throw new Error(`claim: ${claim.status} ${JSON.stringify(claim.body)}`);
  const verify = await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: opts.token });
  if (verify.status !== 202) throw new Error(`verify: ${verify.status} ${JSON.stringify(verify.body)}`);
  const nonce = await liveNonce(tel);
  const res = await api("POST", "/v0/challenge-response", { json: { tel, nonce, signature: await key.sign(tel, nonce) } });
  if (res.status !== 200) throw new Error(`challenge-response: ${res.status} ${JSON.stringify(res.body)}`);
  return { tel, key, claimId: claim.body.id as string, entry: res.body as { tel: string; record: string } };
}
