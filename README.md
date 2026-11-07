# phone2mcp registry (prototype)

A registry that binds a phone number to an MCP server, so a buyer agent can skip the phone call and connect directly. It implements the prototype registry from the *phone2mcp Draft Spec v0.1*. It runs entirely on Cloudflare Workers.

| Component | Used for |
| --- | --- |
| Hono on Workers, Zod | REST API |
| D1 | Accounts, claims, bindings, revocations, challenge log |
| KV | Signed records for public lookups (`tel:<E.164>`) |
| Durable Objects | `ChallengeDO`, one per number: the nonce, call state and timeout alarm |
| Cron Triggers | Daily re-signing, re-verification, held takeovers and the expiry sweep, every 15 minutes |
| jose + WebCrypto | Ed25519 JWS records |
| Telnyx Call Control | Outbound verification call that speaks the nonce |
| Workers Rate Limiting | Per-IP limits on lookups and challenge responses |

## How verification works

1. A registrant creates a claim with `POST /v0/claims`. The claim holds the number, the MCP URL and the server's Ed25519 public key.
2. `POST /v0/claims/{id}/verify` starts a challenge. The `ChallengeDO` for that number creates an 8-digit nonce and dials the number through Telnyx.
3. When the call is answered, the registry speaks the nonce up to three times and then hangs up.
4. The answering agent passes the nonce to its MCP backend. The backend signs it and calls `POST /v0/challenge-response`:

   ```json
   { "tel": "+16025550100", "nonce": "48151623", "signature": "<base64url Ed25519 signature>" }
   ```

   The signed bytes are `challengeResponseMessage(tel, nonce)` from [`src/protocol.ts`](src/protocol.ts):

   ```
   phone2mcp/0.1 challenge-response\n<tel>\n<nonce>
   ```

5. The registry checks the signature against the claimed `server_key` and then checks the nonce. If both pass, it signs a binding record, stores it in D1 and KV, and returns it.

Failure handling:

- A response with a bad signature is rejected and does not count as an attempt, so only the key holder can use up attempts.
- Three validly signed wrong nonces fail the challenge.
- If nobody answers the call, the challenge fails straight away.
- Otherwise a challenge times out after `CHALLENGE_TTL_SECONDS`, which defaults to 180.
- Repeated Telnyx webhooks are applied only once, matched by event id.

Each number's `ChallengeDO` is the only writer of that number's binding in D1 and KV. It runs issuance, deletion, failure handling and expiry one at a time, so they can't interleave.

Verification calls cost money and ring a real phone, so they are capped. Claim calls are limited to `CLAIM_CALLS_PER_NUMBER_PER_HOUR` (default 3) per number and `CLAIM_CALLS_PER_ACCOUNT_PER_DAY` (default 500) per account.

### Record lifetime and re-verification

Two timers run separately:

- **A signed record lasts 48 hours** (`RECORD_TTL_SECONDS`). The cron re-signs it, with no call, once it has less than 24 hours left (`RECORD_REFRESH_SECONDS`). Buyers can't check revocation, so this bounds how long a revoked or superseded record keeps verifying: at most 48 hours.
- **A call-back verification lasts 14 days** (`VERIFICATION_TTL_SECONDS`), tracked as the binding's `verified_until`. A record is never signed past it, and the binding expires when it runs out.

This departs from the spec's default of a 14-day record `exp`.

Each binding gets a random re-verification time between 40% and 75% of its verification window. The cron job re-challenges bindings that are due. Failures are handled as follows:

- **Soft failure** (no answer or timeout): retried after `REVERIFY_RETRY_SECONDS`. The binding is revoked after `REVERIFY_MAX_FAILURES` failures, or when no retry fits before `verified_until`.
- **Hard failure** (validly signed wrong nonces): the binding is revoked at once.

### Takeovers

When a different account proves control of a number that is already bound, the number does not switch at once:

1. The claim goes to `held` for `TAKEOVER_HOLD_SECONDS` (48 hours), and the current binding keeps working. The challenge response returns `202` with `takeover_after`.
2. When the hold ends, the registry calls the number again (challenge kind `takeover`).
3. A second success switches the number, and the old record is revoked as `superseded`. A failure fails the claim and leaves the current binding alone.

A brief call-forwarding or SIM-swap hijack can't pass two calls 48 hours apart. The same account moving its own number switches at once. Setting `TAKEOVER_HOLD_SECONDS=0` turns the hold off.

If the MCP URL changed, lookups carry an unsigned `mcp_url_changed_at` hint, and a claim for an already-bound number returns a warning.

## API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/.well-known/registry-keys` | public | JWKS of the registry's signing keys |
| GET | `/v0/lookup/{tel}` | public, rate-limited | `{ tel, record }` or 404 |
| POST | `/v0/lookup` | public, rate-limited | `{ tels: [...] }` with up to 50 numbers, returns `{ results: [{ tel, record \| null }] }` |
| POST | `/v0/challenge-response` | public, rate-limited | Called by the MCP server with the signed nonce |
| POST | `/v0/claims` | API key | Start a claim: `{ tel, mcp_url, server_key, registrant, attest_control: true }` |
| GET | `/v0/claims/{id}` | API key | Claim status: `pending`, `verifying`, `held`, `verified`, `failed`, `superseded`, `revoked` or `expired` |
| POST | `/v0/claims/{id}/verify` | API key | Place the call-back challenge |
| DELETE | `/v0/bindings/{tel}` | API key | Remove your binding and revoke its record |
| POST | `/v0/admin/accounts` | `ADMIN_TOKEN` | Create a registrant account: `{ name, operator? }`. Returns the API key once. |
| POST | `/v0/telephony/telnyx` | Telnyx signature | Call Control webhooks |

`record` is a compact JWS with the header `{"alg":"EdDSA","kid":…,"typ":"phone2mcp-binding+jwt"}`. Its payload is the binding record from the spec. Buyer agents must verify it against `/.well-known/registry-keys` and check `exp`.

The account's `operator` domain is written to records as `operator` when it differs from the claim's `registrant`. This lets a vendor such as Callingly claim numbers for its customers.

## Development

```bash
npm install --legacy-peer-deps
```

```bash
npm test
```

```bash
npm run typecheck
```

Tests run inside the Workers runtime with `@cloudflare/vitest-plugin`. They use the `mock` telephony provider and read the nonce straight from the `ChallengeDO`.

To run the Worker locally, set up `.dev.vars`:

```bash
cp .dev.vars.example .dev.vars
```

Generate a signing key, and put its output in `REGISTRY_SIGNING_JWK` in `.dev.vars`:

```bash
node scripts/gen-signing-key.mjs
```

Then apply the migrations and start the Worker:

```bash
npm run db:migrate:local
```

```bash
npm run dev
```

## Deploying

1. Create the D1 database and the KV namespace, and put their ids in `wrangler.jsonc`:

   ```bash
   npx wrangler d1 create phone2mcp
   ```

   ```bash
   npx wrangler kv namespace create RECORDS
   ```

2. Apply the migrations:

   ```bash
   npm run db:migrate
   ```

3. Set the secrets:

   ```bash
   node scripts/gen-signing-key.mjs | npx wrangler secret put REGISTRY_SIGNING_JWK
   ```

   ```bash
   npx wrangler secret put ADMIN_TOKEN
   ```

   ```bash
   npx wrangler secret put TELNYX_API_KEY
   ```

   ```bash
   npx wrangler secret put TELNYX_PUBLIC_KEY
   ```

4. Set `TELNYX_CONNECTION_ID` and `TELNYX_FROM_NUMBER` in `wrangler.jsonc`. The Worker is served at `registry.phone2mcp.com` as a custom domain, and `PUBLIC_BASE_URL` already points there. The Call Control application needs no webhook URL of its own, because each call sets its own.
5. Deploy:

   ```bash
   npm run deploy
   ```

**Key rotation:** generate a new key, and move the old key's public JWK into `REGISTRY_RETIRED_JWKS` (a JSON array) so that records it already signed keep verifying until they expire.

## Status against the spec's build order

- [x] 1. Record format, signing, public lookup and keys endpoints
- [x] 2. Claim endpoints with API-key auth for registrants
- [x] 3. Verifier: outbound Telnyx call speaking the nonce, plus the challenge-response endpoint that issues the record
- [x] 4. Expiry, cron re-verification and rate limiting
- [ ] 5. TypeScript client library for buyer agents (`src/protocol.ts` holds the shared formats to build it on)

Not done yet:

- The Telnyx integration has not been tested against a live account.
- The nonce is spoken only, not sent as DTMF (an open question in the spec).
- There is no revocation list endpoint. Buyers rely on the 48-hour record lifetime.
- **Robocall rules (TCPA).** The registry places automated, artificial-voice calls. Every claim must carry `attest_control: true`, meaning the registrant attests it controls the number and consents to the call; the time is stored as `attested_at`. Only admin-created accounts can make claims. A TCPA review is still needed before opening self-serve sign-ups.
- The current registrant isn't notified when a takeover is held, because the registry has no notification channel yet.

## License

Apache 2.0
