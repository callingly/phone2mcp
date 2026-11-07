import { env, runDurableObjectAlarm } from "cloudflare:test";
import { mockTelephony } from "../src/telephony";
import { compactVerify, createLocalJWKSet, decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { runScheduled } from "../src/cron";
import { RECORD_TYP, type BindingRecord } from "../src/protocol";
import { api, bindNumber, challengeStub, createAccount, freshTel, liveNonce, serverKey } from "./helpers";

async function verifyRecord(jws: string): Promise<BindingRecord> {
  const keys = await api("GET", "/.well-known/registry-keys");
  const { payload } = await compactVerify(jws, createLocalJWKSet(keys.body), { algorithms: ["EdDSA"] });
  return JSON.parse(new TextDecoder().decode(payload));
}

describe("registry keys", () => {
  it("publishes the public signing key only", async () => {
    const res = await api("GET", "/.well-known/registry-keys");
    expect(res.status).toBe(200);
    expect(res.body.keys).toHaveLength(1);
    expect(res.body.keys[0]).toMatchObject({ kty: "OKP", crv: "Ed25519", kid: "test-key", alg: "EdDSA" });
    expect(res.body.keys[0].d).toBeUndefined();
  });
});

describe("lookup", () => {
  it("returns 404 for an unbound number and 400 for a malformed one", async () => {
    expect((await api("GET", `/v0/lookup/${freshTel()}`)).status).toBe(404);
    expect((await api("GET", "/v0/lookup/6025550100")).status).toBe(400);
  });

  it("rejects batches over 50 numbers", async () => {
    const tels = Array.from({ length: 51 }, () => freshTel());
    expect((await api("POST", "/v0/lookup", { json: { tels } })).status).toBe(400);
  });
});

describe("claims", () => {
  it("requires an API key", async () => {
    expect((await api("POST", "/v0/claims", { json: {} })).status).toBe(401);
    expect((await api("POST", "/v0/claims", { token: "p2m_nope", json: {} })).status).toBe(401);
  });

  it("validates input", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const bad = [
      { tel: "6025550100", mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
      { tel: freshTel(), mcp_url: "http://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
      { tel: freshTel(), mcp_url: "https://a.example/mcp", server_key: "abc", registrant: "a.example", attest_control: true },
      { tel: freshTel(), mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "not a domain", attest_control: true },
    ];
    for (const json of bad) expect((await api("POST", "/v0/claims", { token: api_key, json })).status).toBe(400);
  });

  it("requires the registrant to attest it controls the number", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const json = { tel: freshTel(), mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example" };
    const missing = await api("POST", "/v0/claims", { token: api_key, json });
    expect(missing.status).toBe(400);
    expect(missing.body.details.attest_control).toBeDefined();
    expect((await api("POST", "/v0/claims", { token: api_key, json: { ...json, attest_control: false } })).status).toBe(400);
    const ok = await api("POST", "/v0/claims", { token: api_key, json: { ...json, attest_control: true } });
    expect(ok.status).toBe(201);
    expect(ok.body.attested_at).toBeTypeOf("number");
  });

  it("hides claims from other accounts", async () => {
    const a = await createAccount();
    const b = await createAccount();
    const key = await serverKey();
    const claim = await api("POST", "/v0/claims", {
      token: a.api_key,
      json: { tel: freshTel(), mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    expect(claim.status).toBe(201);
    expect(claim.body).toMatchObject({ status: "pending", operator: "callingly.com" });
    expect((await api("GET", `/v0/claims/${claim.body.id}`, { token: a.api_key })).status).toBe(200);
    expect((await api("GET", `/v0/claims/${claim.body.id}`, { token: b.api_key })).status).toBe(404);
    expect((await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: b.api_key })).status).toBe(404);
  });

  it("omits operator when the registrant is the operator", async () => {
    const { api_key } = await createAccount("acme.example");
    const { entry } = await bindNumber({ token: api_key, registrant: "acme.example" });
    expect((await verifyRecord(entry.record)).operator).toBeUndefined();
  });
});

describe("call-back verification", () => {
  it("issues a signed record when the MCP server returns the spoken nonce", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const tel = freshTel();
    const claim = await api("POST", "/v0/claims", {
      token: api_key,
      json: { tel, mcp_url: "https://mcp.acmeplumbing.com/mcp", server_key: key.publicKey, registrant: "acmeplumbing.com", attest_control: true },
    });
    const verify = await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });
    expect(verify.status).toBe(202);
    expect(verify.body.challenge_id).toMatch(/^chl_/);
    expect((await api("GET", `/v0/claims/${claim.body.id}`, { token: api_key })).body.status).toBe("verifying");

    // A second challenge for the same number is refused while one is live.
    expect((await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key })).status).toBe(409);

    const nonce = await liveNonce(tel);
    expect(nonce).toMatch(/^\d{8}$/);

    // Signed by a different key: rejected, and does not use up an attempt.
    const other = await serverKey();
    const forged = await api("POST", "/v0/challenge-response", { json: { tel, nonce, signature: await other.sign(tel, nonce) } });
    expect(forged.status).toBe(401);

    const res = await api("POST", "/v0/challenge-response", { json: { tel, nonce, signature: await key.sign(tel, nonce) } });
    expect(res.status).toBe(200);
    expect(res.body.tel).toBe(tel);

    expect(decodeProtectedHeader(res.body.record)).toMatchObject({ alg: "EdDSA", kid: "test-key", typ: RECORD_TYP });
    const record = await verifyRecord(res.body.record);
    expect(record).toMatchObject({
      v: "0.1",
      tel,
      mcp_url: "https://mcp.acmeplumbing.com/mcp",
      server_key: key.publicKey,
      registrant: "acmeplumbing.com",
      operator: "callingly.com",
      verified_by: ["callback"],
    });
    // Records are short-lived; the call-back verification lasts 14 days.
    expect(record.exp - record.iat).toBe(48 * 3600);
    const row = await env.DB.prepare("SELECT verified_at, verified_until FROM bindings WHERE tel = ?")
      .bind(tel)
      .first<{ verified_at: number; verified_until: number }>();
    expect(row!.verified_until - row!.verified_at).toBe(14 * 24 * 3600);
    expect(record.jti).toBeTruthy();

    // The nonce is single-use.
    expect((await api("POST", "/v0/challenge-response", { json: { tel, nonce, signature: await key.sign(tel, nonce) } })).status).toBe(404);

    const looked = await api("GET", `/v0/lookup/${encodeURIComponent(tel)}`);
    expect(looked.status).toBe(200);
    expect(looked.body.record).toBe(res.body.record);

    const batch = await api("POST", "/v0/lookup", { json: { tels: [tel, "+16025550000"] } });
    expect(batch.body.results).toEqual([
      { tel, record: res.body.record },
      { tel: "+16025550000", record: null },
    ]);

    expect((await api("GET", `/v0/claims/${claim.body.id}`, { token: api_key })).body.status).toBe("verified");
  });

  it("accepts only one of two simultaneous correct responses", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const tel = freshTel();
    const claim = await api("POST", "/v0/claims", {
      token: api_key,
      json: { tel, mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });
    const nonce = await liveNonce(tel);
    const json = { tel, nonce, signature: await key.sign(tel, nonce) };
    const results = await Promise.all([api("POST", "/v0/challenge-response", { json }), api("POST", "/v0/challenge-response", { json })]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 404]);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM bindings WHERE tel = ?").bind(tel).first<{ n: number }>();
    expect(count?.n).toBe(1);
  });

  it("limits how often a number can be called for claims", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const tel = freshTel();
    const claim = await api("POST", "/v0/claims", {
      token: api_key,
      json: { tel, mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    for (let i = 0; i < 3; i++) {
      expect((await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key })).status).toBe(202);
      await runDurableObjectAlarm(challengeStub(tel));
    }
    const fourth = await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });
    expect(fourth).toMatchObject({ status: 429, body: { error: "number_cooldown" } });
  });

  it("fails the claim after three wrong nonces", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const tel = freshTel();
    const claim = await api("POST", "/v0/claims", {
      token: api_key,
      json: { tel, mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });
    const nonce = await liveNonce(tel);
    const wrong = nonce === "00000000" ? "11111111" : "00000000";
    const respond = async () => api("POST", "/v0/challenge-response", { json: { tel, nonce: wrong, signature: await key.sign(tel, wrong) } });
    expect((await respond()).body.error).toBe("wrong_nonce");
    expect((await respond()).body.error).toBe("wrong_nonce");
    expect((await respond()).body.error).toBe("challenge_failed");
    const after = await api("GET", `/v0/claims/${claim.body.id}`, { token: api_key });
    expect(after.body).toMatchObject({ status: "failed", failure_reason: "too_many_wrong_nonces" });

    // A failed claim can be retried.
    expect((await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key })).status).toBe(202);
  });

  it("fails the claim when the challenge times out", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const tel = freshTel();
    const claim = await api("POST", "/v0/claims", {
      token: api_key,
      json: { tel, mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });
    expect(await runDurableObjectAlarm(challengeStub(tel))).toBe(true);
    expect(await challengeStub(tel).inspect()).toBeUndefined();
    const after = await api("GET", `/v0/claims/${claim.body.id}`, { token: api_key });
    expect(after.body).toMatchObject({ status: "failed", failure_reason: "timeout" });
  });
});

describe("Telnyx webhooks", () => {
  async function signedWebhook(body: unknown, opts: { tamper?: boolean } = {}) {
    const raw = JSON.stringify(body);
    const ts = String(Math.floor(Date.now() / 1000));
    const jwk = JSON.parse(env.TEST_TELNYX_PRIVATE_JWK);
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(`${ts}|${raw}`)));
    const headers = {
      "content-type": "application/json",
      "telnyx-timestamp": ts,
      "telnyx-signature-ed25519": btoa(String.fromCharCode(...sig)),
    };
    const { SELF } = await import("cloudflare:test");
    return SELF.fetch("https://registry.test/v0/telephony/telnyx", {
      method: "POST",
      headers,
      body: opts.tamper ? raw.replace("call.", "call.x") : raw,
    });
  }

  const event = (type: string, tel: string, challengeId: string, extra: object = {}) => ({
    data: {
      event_type: type,
      payload: { call_control_id: "v3:call-1", client_state: btoa(JSON.stringify({ c: challengeId, t: tel })), ...extra },
    },
  });

  it("rejects unsigned or tampered webhooks", async () => {
    expect((await api("POST", "/v0/telephony/telnyx", { json: { data: {} } })).status).toBe(401);
    expect((await signedWebhook(event("call.answered", "+16025550100", "chl_x"), { tamper: true })).status).toBe(401);
  });

  it("applies a redelivered webhook only once", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const tel = freshTel();
    const claim = await api("POST", "/v0/claims", {
      token: api_key,
      json: { tel, mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    const { body } = await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });
    await signedWebhook(event("call.answered", tel, body.challenge_id));
    const base = event("call.speak.ended", tel, body.challenge_id);
    const ended = { data: { ...base.data, id: "evt-1" } };
    await signedWebhook(ended);
    await signedWebhook(ended);
    expect((await challengeStub(tel).inspect())?.spoken).toBe(1);
  });

  it("retries speech when Telnyx rejects it and the webhook is redelivered", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const tel = freshTel();
    const claim = await api("POST", "/v0/claims", {
      token: api_key,
      json: { tel, mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    const { body } = await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });
    const answered = { data: { ...event("call.answered", tel, body.challenge_id).data, id: "evt-answer" } };

    const realSpeak = mockTelephony.speak;
    const spoken: string[] = [];
    mockTelephony.speak = async () => {
      throw new Error("telnyx 503");
    };
    try {
      expect((await signedWebhook(answered)).status).toBe(503);
    } finally {
      mockTelephony.speak = async (_id, text) => {
        spoken.push(text);
      };
    }
    expect((await challengeStub(tel).inspect())?.status).toBe("dialing");

    expect((await signedWebhook(answered)).status).toBe(200);
    mockTelephony.speak = realSpeak;
    expect(spoken).toHaveLength(1);
    expect(await challengeStub(tel).inspect()).toMatchObject({ status: "answered", seenEvents: ["evt-answer"] });
  });

  it("tracks the call and fails fast when nobody answers", async () => {
    const { api_key } = await createAccount();
    const key = await serverKey();
    const tel = freshTel();
    const claim = await api("POST", "/v0/claims", {
      token: api_key,
      json: { tel, mcp_url: "https://a.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    const { body } = await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });

    expect((await signedWebhook(event("call.answered", tel, body.challenge_id))).status).toBe(200);
    expect(await challengeStub(tel).inspect()).toMatchObject({ status: "answered", callId: "v3:call-1" });
    await signedWebhook(event("call.speak.ended", tel, body.challenge_id));
    expect((await challengeStub(tel).inspect())?.spoken).toBe(1);

    // After an answer, hangup does not end the challenge: the server may still respond.
    await signedWebhook(event("call.hangup", tel, body.challenge_id, { hangup_cause: "normal_clearing" }));
    expect(await challengeStub(tel).inspect()).toBeDefined();

    // Fresh challenge that is never answered.
    await runDurableObjectAlarm(challengeStub(tel));
    const retry = await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: api_key });
    await signedWebhook(event("call.hangup", tel, retry.body.challenge_id, { hangup_cause: "timeout" }));
    expect(await challengeStub(tel).inspect()).toBeUndefined();
    const after = await api("GET", `/v0/claims/${claim.body.id}`, { token: api_key });
    expect(after.body).toMatchObject({ status: "failed", failure_reason: "no_answer:timeout" });
  });
});

describe("bindings", () => {
  it("lets the owning registrant delete a binding, revoking its record", async () => {
    const owner = await createAccount();
    const other = await createAccount();
    const { tel, entry } = await bindNumber({ token: owner.api_key });
    const { jti } = await verifyRecord(entry.record);

    expect((await api("DELETE", `/v0/bindings/${tel}`, { token: other.api_key })).status).toBe(404);
    expect((await api("DELETE", `/v0/bindings/${tel}`, { token: owner.api_key })).status).toBe(204);
    expect((await api("GET", `/v0/lookup/${tel}`)).status).toBe(404);
    const rev = await env.DB.prepare("SELECT reason FROM revocations WHERE jti = ?").bind(jti).first();
    expect(rev).toEqual({ reason: "registrant_deleted" });
  });

  it("holds a takeover by another account until a second call-back confirms it", async () => {
    const first = await createAccount();
    const second = await createAccount("othervendor.example");
    const { tel, entry: old } = await bindNumber({ token: first.api_key, mcp_url: "https://old.example/mcp" });

    const key = await serverKey();
    const claim = await api("POST", "/v0/claims", {
      token: second.api_key,
      json: { tel, mcp_url: "https://new.example/mcp", server_key: key.publicKey, registrant: "acmeplumbing.com", attest_control: true },
    });
    expect(claim.body.warnings).toEqual(["number_already_bound_to_different_mcp_url"]);
    await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: second.api_key });
    let nonce = await liveNonce(tel);
    const first_proof = await api("POST", "/v0/challenge-response", { json: { tel, nonce, signature: await key.sign(tel, nonce) } });
    expect(first_proof.status).toBe(202);
    expect(first_proof.body).toMatchObject({ tel, status: "takeover_pending" });

    // During the hold the current binding keeps working, and the claim can't be re-verified early.
    const held = await api("GET", `/v0/claims/${claim.body.id}`, { token: second.api_key });
    expect(held.body.status).toBe("held");
    expect(held.body.takeover_after - Math.floor(Date.now() / 1000)).toBeGreaterThan(47 * 3600);
    expect((await api("GET", `/v0/lookup/${tel}`)).body.record).toBe(old.record);
    expect((await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: second.api_key })).status).toBe(409);
    expect((await runScheduled(env)).takeovers).toBe(0);

    // The hold ends: the registry calls again, and a second success switches the number.
    await env.DB.prepare("UPDATE claims SET takeover_after = 0 WHERE id = ?").bind(claim.body.id).run();
    expect((await runScheduled(env)).takeovers).toBe(1);
    expect((await challengeStub(tel).inspect())?.kind).toBe("takeover");
    nonce = await liveNonce(tel);
    const confirmed = await api("POST", "/v0/challenge-response", { json: { tel, nonce, signature: await key.sign(tel, nonce) } });
    expect(confirmed.status).toBe(200);

    const looked = await api("GET", `/v0/lookup/${tel}`);
    expect(looked.body.record).toBe(confirmed.body.record);
    expect(looked.body.mcp_url_changed_at).toBeTypeOf("number");
    expect((await verifyRecord(confirmed.body.record)).operator).toBe("othervendor.example");
    expect((await api("GET", `/v0/claims/${claim.body.id}`, { token: second.api_key })).body.status).toBe("verified");

    const { jti } = await verifyRecord(old.record);
    expect(await env.DB.prepare("SELECT reason FROM revocations WHERE jti = ?").bind(jti).first()).toEqual({ reason: "superseded" });
    // The first registrant no longer owns it.
    expect((await api("DELETE", `/v0/bindings/${tel}`, { token: first.api_key })).status).toBe(404);
  });

  it("keeps the current binding when the confirming call-back fails", async () => {
    const first = await createAccount();
    const second = await createAccount();
    const { tel, entry: old } = await bindNumber({ token: first.api_key });

    const key = await serverKey();
    const claim = await api("POST", "/v0/claims", {
      token: second.api_key,
      json: { tel, mcp_url: "https://new.example/mcp", server_key: key.publicKey, registrant: "a.example", attest_control: true },
    });
    await api("POST", `/v0/claims/${claim.body.id}/verify`, { token: second.api_key });
    const nonce = await liveNonce(tel);
    expect((await api("POST", "/v0/challenge-response", { json: { tel, nonce, signature: await key.sign(tel, nonce) } })).status).toBe(202);

    // A brief hijack: by the confirming call the number answers elsewhere, so it times out.
    await env.DB.prepare("UPDATE claims SET takeover_after = 0 WHERE id = ?").bind(claim.body.id).run();
    await runScheduled(env);
    await runDurableObjectAlarm(challengeStub(tel));

    expect((await api("GET", `/v0/claims/${claim.body.id}`, { token: second.api_key })).body).toMatchObject({ status: "failed", failure_reason: "timeout" });
    expect((await api("GET", `/v0/lookup/${tel}`)).body.record).toBe(old.record);
  });

  it("switches at once when the same account moves its own number", async () => {
    const { api_key } = await createAccount();
    const { tel } = await bindNumber({ token: api_key, mcp_url: "https://old.example/mcp" });
    const { entry } = await bindNumber({ token: api_key, tel, mcp_url: "https://new.example/mcp" });
    expect((await verifyRecord(entry.record)).mcp_url).toBe("https://new.example/mcp");
    expect((await api("GET", `/v0/lookup/${tel}`)).body.record).toBe(entry.record);
  });
});

describe("scheduled re-verification", () => {
  const makeDue = (tel: string) =>
    env.DB.prepare("UPDATE bindings SET next_reverify_at = 0 WHERE tel = ?").bind(tel).run();

  it("schedules re-verification at a random point mid-verification", async () => {
    const { api_key } = await createAccount();
    const { tel } = await bindNumber({ token: api_key });
    const row = await env.DB.prepare("SELECT next_reverify_at, verified_at, verified_until FROM bindings WHERE tel = ?")
      .bind(tel)
      .first<{ next_reverify_at: number; verified_at: number; verified_until: number }>();
    const ttl = row!.verified_until - row!.verified_at;
    expect(row!.next_reverify_at).toBeGreaterThanOrEqual(row!.verified_at + 0.4 * ttl - 1);
    expect(row!.next_reverify_at).toBeLessThanOrEqual(row!.verified_at + 0.75 * ttl);
  });

  it("re-signs records nearing expiry without a call", async () => {
    const { api_key } = await createAccount();
    const { tel, entry } = await bindNumber({ token: api_key });
    const before = await verifyRecord(entry.record);
    const now = Math.floor(Date.now() / 1000);
    // Not yet in the refresh window: untouched.
    expect((await runScheduled(env)).resigned).toBe(0);

    await env.DB.prepare("UPDATE bindings SET exp = ? WHERE tel = ?").bind(now + 3600, tel).run();
    expect((await runScheduled(env)).resigned).toBeGreaterThanOrEqual(1);
    expect(await challengeStub(tel).inspect()).toBeUndefined(); // no call placed

    const looked = await api("GET", `/v0/lookup/${tel}`);
    const after = await verifyRecord(looked.body.record);
    expect(after.jti).not.toBe(before.jti);
    expect(after.exp - after.iat).toBe(48 * 3600);
    const row = await env.DB.prepare("SELECT jti, verified_until FROM bindings WHERE tel = ?").bind(tel).first<{ jti: string; verified_until: number }>();
    expect(row!.jti).toBe(after.jti);
  });

  it("retries a re-sign whose KV write failed", async () => {
    const { api_key } = await createAccount();
    const { tel, entry } = await bindNumber({ token: api_key });
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare("UPDATE bindings SET exp = ? WHERE tel = ?").bind(now + 3600, tel).run();

    const realPut = env.RECORDS.put.bind(env.RECORDS);
    env.RECORDS.put = (async () => {
      throw new Error("kv unavailable");
    }) as typeof env.RECORDS.put;
    try {
      expect((await runScheduled(env)).resigned).toBe(0);
    } finally {
      env.RECORDS.put = realPut;
    }
    // Nothing was saved, so the record is still due and the old one still served.
    const row = await env.DB.prepare("SELECT exp FROM bindings WHERE tel = ?").bind(tel).first<{ exp: number }>();
    expect(row!.exp).toBe(now + 3600);
    expect((await api("GET", `/v0/lookup/${tel}`)).body.record).toBe(entry.record);

    expect((await runScheduled(env)).resigned).toBeGreaterThanOrEqual(1);
    expect((await api("GET", `/v0/lookup/${tel}`)).body.record).not.toBe(entry.record);
  });

  it("never re-signs a record past the binding's verification", async () => {
    const { api_key } = await createAccount();
    const { tel } = await bindNumber({ token: api_key });
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare("UPDATE bindings SET exp = ?, verified_until = ?, next_reverify_at = ? WHERE tel = ?")
      .bind(now + 600, now + 7200, now + 999999, tel)
      .run();
    await runScheduled(env);
    const after = await verifyRecord((await api("GET", `/v0/lookup/${tel}`)).body.record);
    expect(after.exp).toBe(now + 7200);
    // Already at verified_until: nothing left to extend.
    expect((await runScheduled(env)).resigned).toBe(0);
  });

  it("re-challenges due bindings and renews the record on success", async () => {
    const { api_key } = await createAccount();
    const { tel, key, entry } = await bindNumber({ token: api_key });
    await makeDue(tel);
    const r = await runScheduled(env);
    expect(r.started).toBeGreaterThanOrEqual(1);
    expect((await challengeStub(tel).inspect())?.kind).toBe("reverify");

    const nonce = await liveNonce(tel);
    const res = await api("POST", "/v0/challenge-response", { json: { tel, nonce, signature: await key.sign(tel, nonce) } });
    expect(res.status).toBe(200);
    expect(res.body.record).not.toBe(entry.record);
    expect((await verifyRecord(res.body.record)).jti).not.toBe((await verifyRecord(entry.record)).jti);
    expect((await api("GET", `/v0/lookup/${tel}`)).body.record).toBe(res.body.record);
  });

  it("retries after missed calls and revokes after the failure limit", async () => {
    const { api_key } = await createAccount();
    const { tel } = await bindNumber({ token: api_key });
    for (let i = 1; i <= 3; i++) {
      await makeDue(tel);
      await runScheduled(env);
      await runDurableObjectAlarm(challengeStub(tel));
      const row = await env.DB.prepare("SELECT reverify_failures FROM bindings WHERE tel = ?").bind(tel).first<{ reverify_failures: number }>();
      if (i < 3) expect(row?.reverify_failures).toBe(i);
      else expect(row).toBeNull();
    }
    expect((await api("GET", `/v0/lookup/${tel}`)).status).toBe(404);
  });

  it("revokes immediately when re-verification gets wrong answers", async () => {
    const { api_key } = await createAccount();
    const { tel, key } = await bindNumber({ token: api_key });
    await makeDue(tel);
    await runScheduled(env);
    const nonce = await liveNonce(tel);
    const wrong = nonce === "00000000" ? "11111111" : "00000000";
    for (let i = 0; i < 3; i++) {
      await api("POST", "/v0/challenge-response", { json: { tel, nonce: wrong, signature: await key.sign(tel, wrong) } });
    }
    expect((await api("GET", `/v0/lookup/${tel}`)).status).toBe(404);
  });

  it("sweeps bindings whose verification ran out", async () => {
    const { api_key } = await createAccount();
    const { tel, claimId } = await bindNumber({ token: api_key });
    await env.DB.prepare("UPDATE bindings SET verified_until = 1 WHERE tel = ?").bind(tel).run();
    await runScheduled(env);
    expect(await env.DB.prepare("SELECT tel FROM bindings WHERE tel = ?").bind(tel).first()).toBeNull();
    expect((await api("GET", `/v0/claims/${claimId}`, { token: api_key })).body.status).toBe("expired");
  });
});
