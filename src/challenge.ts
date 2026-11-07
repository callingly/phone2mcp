import { DurableObject } from "cloudflare:workers";
import { config, type Env } from "./env";
import { randomDigits, randomId, timingSafeEqual, verifyEd25519 } from "./crypto";
import { challengeFailed, challengeStarted, issueBinding, type ChallengeSubject, type LookupEntry } from "./bindings";
import { challengeScript, telephony, type CallState, type TelephonyEvent } from "./telephony";
import { base64urlDecode, challengeResponseMessage } from "./protocol";

/** How many times the nonce is spoken before the registry hangs up. */
const SPEAK_REPEATS = 3;
/** Validly signed but wrong nonces allowed before the challenge fails. */
const MAX_ATTEMPTS = 3;

export interface ChallengeState extends ChallengeSubject {
  nonce: string;
  serverKey: string;
  status: "dialing" | "answered";
  callId?: string;
  spoken: number;
  attempts: number;
}

export interface BeginInput {
  tel: string;
  claimId: string;
  serverKey: string;
  kind: ChallengeSubject["kind"];
}

export type BeginResult =
  | { ok: true; challengeId: string; expiresAt: number }
  | { ok: false; error: "challenge_in_progress" | "call_failed"; challengeId?: string };

export type RespondResult =
  | { ok: true; binding: LookupEntry }
  | { ok: false; status: 400 | 401 | 404 | 409; error: string };

/**
 * One instance per phone number (`idFromName(tel)`), so a number has at most
 * one live challenge. Holds the nonce and a timeout alarm.
 */
export class ChallengeDO extends DurableObject<Env> {
  private async load(): Promise<ChallengeState | undefined> {
    const s = await this.ctx.storage.get<ChallengeState>("state");
    return s && s.expiresAt > Date.now() ? s : undefined;
  }

  private callState(s: ChallengeState): CallState {
    return { c: s.id, t: s.tel };
  }

  /** Start a challenge and dial the number. */
  async begin(input: BeginInput): Promise<BeginResult> {
    const live = await this.load();
    if (live) return { ok: false, error: "challenge_in_progress", challengeId: live.id };

    const { challengeTtl, nonceDigits } = config(this.env);
    const now = Date.now();
    const state: ChallengeState = {
      id: randomId("chl"),
      tel: input.tel,
      claimId: input.claimId,
      kind: input.kind,
      serverKey: input.serverKey,
      nonce: randomDigits(nonceDigits),
      status: "dialing",
      spoken: 0,
      attempts: 0,
      createdAt: now,
      expiresAt: now + challengeTtl * 1000,
    };
    await this.ctx.storage.put("state", state);
    await this.ctx.storage.setAlarm(state.expiresAt);
    await challengeStarted(this.env, state);

    try {
      const callId = await telephony(this.env).placeCall(state.tel, this.callState(state));
      const current = await this.ctx.storage.get<ChallengeState>("state");
      if (current?.id === state.id) await this.ctx.storage.put("state", { ...current, callId });
    } catch (err) {
      console.error("placeCall failed", err);
      await this.fail(state, "call_failed", false);
      return { ok: false, error: "call_failed", challengeId: state.id };
    }
    return { ok: true, challengeId: state.id, expiresAt: state.expiresAt };
  }

  /** Telephony webhooks, already authenticated by the Worker. */
  async onTelephonyEvent(challengeId: string, event: TelephonyEvent): Promise<void> {
    const s = await this.load();
    const tel = telephony(this.env);
    if (!s || s.id !== challengeId) {
      // A stale call for a finished challenge: make sure it does not linger.
      if (event.type !== "hangup") await tel.hangup(event.callId);
      return;
    }
    switch (event.type) {
      case "answered":
        s.status = "answered";
        s.callId = event.callId;
        await this.ctx.storage.put("state", s);
        await tel.speak(event.callId, challengeScript(s.nonce, 0), this.callState(s));
        return;
      case "speak_ended":
        s.spoken += 1;
        await this.ctx.storage.put("state", s);
        if (s.spoken < SPEAK_REPEATS) await tel.speak(event.callId, challengeScript(s.nonce, s.spoken), this.callState(s));
        else await tel.hangup(event.callId);
        return;
      case "hangup":
        // Hung up before anyone answered: no point waiting for the timeout.
        if (s.status === "dialing") await this.fail(s, `no_answer:${event.cause ?? "unknown"}`, false);
        return;
    }
  }

  /** The MCP server returns the nonce it heard, signed with its server key. */
  async respond(nonce: string, signature: string): Promise<RespondResult> {
    const s = await this.load();
    if (!s) return { ok: false, status: 404, error: "no_active_challenge" };

    let sig: Uint8Array;
    try {
      sig = base64urlDecode(signature);
    } catch {
      return { ok: false, status: 400, error: "invalid_signature_encoding" };
    }
    // Check the signature first, so only the key holder can use up attempts.
    const valid = await verifyEd25519(base64urlDecode(s.serverKey), sig, challengeResponseMessage(s.tel, nonce));
    if (!valid) return { ok: false, status: 401, error: "bad_signature" };

    if (!timingSafeEqual(nonce, s.nonce)) {
      s.attempts += 1;
      if (s.attempts >= MAX_ATTEMPTS) {
        await this.fail(s, "too_many_wrong_nonces", true);
        return { ok: false, status: 400, error: "challenge_failed" };
      }
      await this.ctx.storage.put("state", s);
      return { ok: false, status: 400, error: "wrong_nonce" };
    }

    // Issue before clearing state, so a transient failure can be retried.
    const binding = await issueBinding(this.env, s);
    await this.finish(s);
    if (!binding) return { ok: false, status: 409, error: "binding_removed" };
    return { ok: true, binding };
  }

  /** Test and debugging hook; never exposed over HTTP. */
  async inspect(): Promise<ChallengeState | undefined> {
    return this.load();
  }

  async alarm(): Promise<void> {
    const s = await this.ctx.storage.get<ChallengeState>("state");
    if (s) await this.fail(s, "timeout", false);
  }

  private async finish(s: ChallengeState): Promise<void> {
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
    if (s.callId) await telephony(this.env).hangup(s.callId);
  }

  private async fail(s: ChallengeState, reason: string, hard: boolean): Promise<void> {
    await this.finish(s);
    await challengeFailed(this.env, s, reason, hard);
  }
}
