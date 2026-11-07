import { generateKeyPairSync } from "node:crypto";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Fresh keys per run: the registry signing key and a fake Telnyx webhook key.
const registry = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
const telnyx = generateKeyPairSync("ed25519");
const telnyxPublicRaw = (telnyx.publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(12);

export default defineConfig(async () => {
  const migrations = await readD1Migrations("./migrations");
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            REGISTRY_SIGNING_JWK: JSON.stringify({ ...registry, kid: "test-key" }),
            ADMIN_TOKEN: "test-admin-token",
            TELEPHONY_PROVIDER: "mock",
            TELNYX_PUBLIC_KEY: telnyxPublicRaw.toString("base64"),
            TEST_TELNYX_PRIVATE_JWK: JSON.stringify(telnyx.privateKey.export({ format: "jwk" })),
          },
        },
      }),
    ],
    test: { setupFiles: ["./test/apply-migrations.ts"] },
  };
});
