-- Registrant accounts. Vendors (e.g. an AI answering provider) hold one account
-- and claim numbers on behalf of their customers.
CREATE TABLE accounts (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  operator      TEXT,                 -- domain written to records as `operator`
  api_key_hash  TEXT NOT NULL UNIQUE, -- SHA-256 hex of the API key
  created_at    INTEGER NOT NULL
);

-- A request to bind a number to an MCP server. Becomes a binding once the
-- call-back challenge succeeds.
CREATE TABLE claims (
  id              TEXT PRIMARY KEY,
  account_id      TEXT NOT NULL REFERENCES accounts(id),
  tel             TEXT NOT NULL,
  mcp_url         TEXT NOT NULL,
  server_key      TEXT NOT NULL,
  registrant      TEXT NOT NULL,
  operator        TEXT,
  status          TEXT NOT NULL,      -- pending | verifying | verified | failed | superseded | revoked | expired
  failure_reason  TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
CREATE INDEX claims_tel ON claims(tel);
CREATE INDEX claims_account ON claims(account_id);

-- Active bindings, one per number. The signed record is cached in KV for lookups.
CREATE TABLE bindings (
  tel                 TEXT PRIMARY KEY,
  claim_id            TEXT NOT NULL REFERENCES claims(id),
  account_id          TEXT NOT NULL REFERENCES accounts(id),
  jti                 TEXT NOT NULL,
  record              TEXT NOT NULL,  -- compact JWS
  mcp_url             TEXT NOT NULL,
  server_key          TEXT NOT NULL,
  iat                 INTEGER NOT NULL,
  exp                 INTEGER NOT NULL,
  next_reverify_at    INTEGER NOT NULL,
  reverify_failures   INTEGER NOT NULL DEFAULT 0,
  mcp_url_changed_at  INTEGER,        -- set when a new binding points the number elsewhere
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL
);
CREATE INDEX bindings_next_reverify ON bindings(next_reverify_at);
CREATE INDEX bindings_exp ON bindings(exp);

-- Revoked record ids.
CREATE TABLE revocations (
  jti         TEXT PRIMARY KEY,
  tel         TEXT NOT NULL,
  reason      TEXT NOT NULL,
  revoked_at  INTEGER NOT NULL
);
CREATE INDEX revocations_tel ON revocations(tel);

-- Audit log of call-back challenges. Live state is held by the ChallengeDO.
CREATE TABLE challenges (
  id              TEXT PRIMARY KEY,
  claim_id        TEXT NOT NULL REFERENCES claims(id),
  tel             TEXT NOT NULL,
  kind            TEXT NOT NULL,      -- claim | reverify
  status          TEXT NOT NULL,      -- pending | succeeded | failed
  failure_reason  TEXT,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  resolved_at     INTEGER
);
CREATE INDEX challenges_claim ON challenges(claim_id);
