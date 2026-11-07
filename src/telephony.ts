import type { Env } from "./env";
import { base64Decode } from "./protocol";
import { verifyEd25519 } from "./crypto";

/** Correlates telephony webhooks with the challenge that placed the call. */
export interface CallState {
  /** challenge id */
  c: string;
  /** E.164 number dialed */
  t: string;
}

export interface Telephony {
  /** Dial `to`; returns the provider's call id. */
  placeCall(to: string, state: CallState): Promise<string>;
  speak(callId: string, text: string, state: CallState): Promise<void>;
  hangup(callId: string): Promise<void>;
}

export type TelephonyEvent =
  | { type: "answered"; callId: string }
  | { type: "speak_ended"; callId: string }
  | { type: "hangup"; callId: string; cause?: string };

export function telephony(env: Env): Telephony {
  return (env.TELEPHONY_PROVIDER ?? "telnyx") === "mock" ? mockTelephony : new TelnyxTelephony(env);
}

/** Places no calls. Tests and local dev read the nonce from the ChallengeDO. */
export const mockTelephony: Telephony = {
  async placeCall(_to, state) {
    return `mock-call-${state.c}`;
  },
  async speak() {},
  async hangup() {},
};

/** The words spoken on a verification call. Digits are spaced so TTS reads them one by one. */
export function challengeScript(nonce: string, repeat: number): string {
  const digits = nonce.split("").join(", ");
  return repeat === 0
    ? `Hello. This is an automated phone to M C P verification call. Your verification code is: ${digits}. Again, your code is: ${digits}.`
    : `Your phone to M C P verification code is: ${digits}.`;
}

const TELNYX_API = "https://api.telnyx.com/v2";

export class TelnyxTelephony implements Telephony {
  constructor(private env: Env) {}

  private async post(path: string, body: unknown): Promise<any> {
    if (!this.env.TELNYX_API_KEY) throw new Error("TELNYX_API_KEY is not configured");
    const res = await fetch(`${TELNYX_API}${path}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.env.TELNYX_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`Telnyx ${path} failed: ${res.status} ${await res.text()}`);
    return res.json();
  }

  async placeCall(to: string, state: CallState): Promise<string> {
    const { TELNYX_CONNECTION_ID, TELNYX_FROM_NUMBER, PUBLIC_BASE_URL } = this.env;
    if (!TELNYX_CONNECTION_ID || !TELNYX_FROM_NUMBER || !PUBLIC_BASE_URL) {
      throw new Error("TELNYX_CONNECTION_ID, TELNYX_FROM_NUMBER and PUBLIC_BASE_URL must be configured");
    }
    const res = await this.post("/calls", {
      connection_id: TELNYX_CONNECTION_ID,
      to,
      from: TELNYX_FROM_NUMBER,
      webhook_url: new URL("/v0/telephony/telnyx", PUBLIC_BASE_URL).toString(),
      webhook_url_method: "POST",
      client_state: encodeCallState(state),
      timeout_secs: 30,
      time_limit_secs: 180,
    });
    return res.data.call_control_id as string;
  }

  async speak(callId: string, text: string, state: CallState): Promise<void> {
    await this.post(`/calls/${encodeURIComponent(callId)}/actions/speak`, {
      payload: text,
      voice: this.env.TELNYX_VOICE || "female",
      language: "en-US",
      client_state: encodeCallState(state),
    });
  }

  async hangup(callId: string): Promise<void> {
    try {
      await this.post(`/calls/${encodeURIComponent(callId)}/actions/hangup`, {});
    } catch {
      // The call may already be over.
    }
  }
}

export function encodeCallState(state: CallState): string {
  return btoa(JSON.stringify(state));
}

export function decodeCallState(s: string | null | undefined): CallState | null {
  if (!s) return null;
  try {
    const v = JSON.parse(new TextDecoder().decode(base64Decode(s)));
    return typeof v?.c === "string" && typeof v?.t === "string" ? { c: v.c, t: v.t } : null;
  } catch {
    return null;
  }
}

/** Map a Telnyx Call Control webhook to an event the ChallengeDO understands. */
export function parseTelnyxWebhook(body: any): { state: CallState; event: TelephonyEvent } | null {
  const type = body?.data?.event_type;
  const p = body?.data?.payload;
  const state = decodeCallState(p?.client_state);
  const callId = p?.call_control_id;
  if (!state || typeof callId !== "string") return null;
  switch (type) {
    case "call.answered":
      return { state, event: { type: "answered", callId } };
    case "call.speak.ended":
      return { state, event: { type: "speak_ended", callId } };
    case "call.hangup":
      return { state, event: { type: "hangup", callId, cause: p?.hangup_cause } };
    default:
      return null;
  }
}

/**
 * Telnyx signs `${timestamp}|${rawBody}` with Ed25519.
 * https://developers.telnyx.com/docs/messaging/receive-webhooks
 */
export async function verifyTelnyxSignature(
  publicKeyB64: string,
  rawBody: string,
  signatureB64: string | undefined,
  timestamp: string | undefined,
  toleranceSeconds = 300,
): Promise<boolean> {
  if (!signatureB64 || !timestamp) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > toleranceSeconds) return false;
  try {
    return await verifyEd25519(
      base64Decode(publicKeyB64),
      base64Decode(signatureB64),
      new TextEncoder().encode(`${timestamp}|${rawBody}`),
    );
  } catch {
    return false;
  }
}
