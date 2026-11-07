import { app } from "./app";
import { runScheduled } from "./cron";
import type { Env } from "./env";

export { ChallengeDO } from "./challenge";

export default {
  fetch: app.fetch,
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(runScheduled(env).then((r) => console.log("scheduled", r)));
  },
} satisfies ExportedHandler<Env>;
