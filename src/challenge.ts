import { DurableObject } from "cloudflare:workers";
import { config, type Env } from "./env";
import { randomDigits, randomId, timingSafeEqual, verifyEd25519 } from "./crypto";
import {
  challengeFailed,
  challengeStarted,
  expireBinding,
  issueBinding,
  revokeBinding,
  type ChallengeSubject,
  type LookupEntry,
} from "./bindings";
import { challengeScript, telephony, type CallState, type TelephonyEvent } from "./telephony";
import { base64urlDecode, challengeResponseMessage } from "./protocol";

/** How many times the nonce is spoken before the registry hangs up. */
const SPEAK_REPEATS = 3;
/** Validly signed but wrong nonces allowed before the challenge fails. */
const MAX_ATTEMPTS = 3;
/** Telephony event ids remembered for de-duplicating webhook retries. */
const SEEN_EVENTS = 32;

export interface ChallengeState extends ChallengeSubject {
  nonce: string;
  serverKey: string;
  status: "dialing" | "answered";
  callId?: string;
  spoken: number;
  attempts: number;
  seenEvents: string[];
}

export interface BeginInput {
  tel: string;
  claimId: string;
  serverKey: string;
  kind: ChallengeSubject["kind"];
}

export type BeginResult =
  | { ok: true; challengeId: string; expiresAt: number }
  | { ok: false; error: "challenge_in_progress" | "call_failed" | "number_cooldown"; challengeId?: string };

export type RespondResult =
  | { ok: true; binding: LookupEntry }
  | { ok: false; status: 400 | 401 | 404 | 409; error: string };

/**
 * One instance per phone number (`idFromName(tel)`). It holds the live
 * challenge (nonce, call state, timeout alarm) and is the only writer of the
 * number's binding in D1 and KV. Every entry point runs under `serial`, so
 * issuance, revocation and expiry for a number never interleave, even across
 * the D1, KV and Telnyx awaits where a Durable Object would otherwise accept
 * the next request.
 */
export class ChallengeDO extends DurableObject<Env> {
  private queue: Promise<unknown> = Promise.resolve();

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  private async load(): Promise<ChallengeState | undefined> {
    const s = await this.ctx.storage.get<ChallengeState>("state");
    return s && s.expiresAt > Date.now() ? s : undefined;
  }

  private callState(s: ChallengeState): CallState {
    return { c: s.id, t: s.tel };
  }

  /** Start a challenge and dial the number. */
  begin(input: BeginInput): Promise<BeginResult> {
    return this.serial(async () => {
      const live = await this.load();
      if (live) return { ok: false, error: "challenge_in_progress", challengeId: live.id };

      const { challengeTtl, nonceDigits, claimCallsPerNumberPerHour } = config(this.env);
      const now = Date.now();
      if (input.kind === "claim") {
        // Limit how often registrants can make the registry ring a number.
        const recent = ((await this.ctx.storage.get<number[]>("claimCalls")) ?? []).filter((t) => t > now - 3600_000);
        if (recent.length >= claimCallsPerNumberPerHour) return { ok: false, error: "number_cooldown" };
        await this.ctx.storage.put("claimCalls", [...recent, now]);
      }

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
        seenEvents: [],
        createdAt: now,
        expiresAt: now + challengeTtl * 1000,
      };
      await this.ctx.storage.put("state", state);
      await this.ctx.storage.setAlarm(state.expiresAt);
      await challengeStarted(this.env, state);

      try {
        state.callId = await telephony(this.env).placeCall(state.tel, this.callState(state));
        await this.ctx.storage.put("state", state);
      } catch (err) {
        console.error("placeCall failed", err);
        await this.fail(state, "call_failed", false);
        return { ok: false, error: "call_failed", challengeId: state.id };
      }
      return { ok: true, challengeId: state.id, expiresAt: state.expiresAt };
    });
  }

  /** Telephony webhooks, already authenticated by the Worker. */
  onTelephonyEvent(challengeId: string, event: TelephonyEvent): Promise<void> {
    return this.serial(async () => {
      const s = await this.load();
      const tel = telephony(this.env);
      if (!s || s.id !== challengeId) {
        // A stale call for a finished challenge: make sure it does not linger.
        if (event.type !== "hangup") await tel.hangup(event.callId);
        return;
      }
      // Providers redeliver webhooks, so apply each event once. State, including
      // the event id, is saved only after the Telnyx action succeeds: if it
      // throws, the webhook fails and Telnyx's redelivery retries it.
      if (event.eventId && s.seenEvents.includes(event.eventId)) return;
      const next: ChallengeState = {
        ...s,
        seenEvents: event.eventId ? [...s.seenEvents, event.eventId].slice(-SEEN_EVENTS) : s.seenEvents,
      };
      switch (event.type) {
        case "answered":
          if (s.status !== "answered") {
            await tel.speak(event.callId, challengeScript(s.nonce, 0), this.callState(s));
            Object.assign(next, { status: "answered", callId: event.callId });
          }
          break;
        case "speak_ended":
          next.spoken = s.spoken + 1;
          if (next.spoken < SPEAK_REPEATS) await tel.speak(event.callId, challengeScript(s.nonce, next.spoken), this.callState(s));
          else await tel.hangup(event.callId);
          break;
        case "hangup":
          // Hung up before anyone answered: no point waiting for the timeout.
          if (s.status === "dialing") return this.fail(s, `no_answer:${event.cause ?? "unknown"}`, false);
          break;
      }
      await this.ctx.storage.put("state", next);
    });
  }

  /** The MCP server returns the nonce it heard, signed with its server key. */
  respond(nonce: string, signature: string): Promise<RespondResult> {
    return this.serial(async (): Promise<RespondResult> => {
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
    });
  }

  /** Registrant deletes its binding. False if the number is not bound to `accountId`. */
  deleteBinding(tel: string, accountId: string): Promise<boolean> {
    return this.serial(() => revokeBinding(this.env, tel, "registrant_deleted", { accountId }));
  }

  /** Cron sweep: drop the binding if it is past `exp`. */
  expire(tel: string, nowSec: number): Promise<boolean> {
    return this.serial(() => expireBinding(this.env, tel, nowSec));
  }

  /** Test and debugging hook; never exposed over HTTP. */
  async inspect(): Promise<ChallengeState | undefined> {
    return this.load();
  }

  async alarm(): Promise<void> {
    await this.serial(async () => {
      const s = await this.ctx.storage.get<ChallengeState>("state");
      // A throw here leaves the state in place and the alarm is retried.
      if (s) await this.fail(s, "timeout", false);
    });
  }

  private async finish(s: ChallengeState): Promise<void> {
    await this.ctx.storage.delete("state");
    await this.ctx.storage.deleteAlarm();
    if (s.callId) await telephony(this.env).hangup(s.callId);
  }

  /** Record the failure first: if D1 throws, the state survives for a retry. */
  private async fail(s: ChallengeState, reason: string, hard: boolean): Promise<void> {
    await challengeFailed(this.env, s, reason, hard);
    await this.finish(s);
  }
}
