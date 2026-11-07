import type { D1Migration } from "cloudflare:test";
import type { Env as RegistryEnv } from "../src/env";

declare global {
  namespace Cloudflare {
    interface Env extends RegistryEnv {
      TEST_MIGRATIONS: D1Migration[];
      TEST_TELNYX_PRIVATE_JWK: string;
    }
  }
}
