#!/usr/bin/env node
// Generates an Ed25519 signing key for the registry as a private JWK.
// Usage: node scripts/gen-signing-key.mjs | npx wrangler secret put REGISTRY_SIGNING_JWK
import { generateKeyPairSync } from "node:crypto";

const { privateKey } = generateKeyPairSync("ed25519");
const jwk = privateKey.export({ format: "jwk" });
const kid = `p2m-${new Date().toISOString().slice(0, 10)}-${Math.random().toString(36).slice(2, 8)}`;
process.stdout.write(JSON.stringify({ ...jwk, kid }));
