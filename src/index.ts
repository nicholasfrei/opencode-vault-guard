import { Plugin } from "@opencode/plugin";
import { Error as ToolError } from "@opencode/plugin/promise/tool";
import { parseConfig } from "./config.js";
import type { Config } from "./config.js";
import { BLOCKED, BLOCKED_FRAME, Guard } from "./guard.js";
import { acquireMetrics } from "./metrics.js";
import type { MetricsLease } from "./metrics.js";

export default Plugin.define({
  id: "vault.guard",
  async setup(ctx) {
    // A malformed config still installs closed gates rather than silently unloading protection.
    let guard: Guard | undefined;
    let config: Config | undefined;
    try {
      config = parseConfig(ctx.options);
    } catch {
      console.error("Vault Guard: invalid configuration; model payloads will be withheld.");
    }

    await ctx.session.hook("http.request", async (event) => {
      if (guard) {
        await guard.http(event);
      } else {
        event.request = new Request("https://vault-guard.invalid/blocked", {
          method: "POST", body: "{}", signal: AbortSignal.abort(new Error(BLOCKED)),
        });
      }
      if (event.request.url === "https://vault-guard.invalid/blocked") throw new Error(BLOCKED);
    });
    await ctx.session.hook("experimental.ws.send", async (event) => {
      if (guard) await guard.websocket(event);
      else event.frame = BLOCKED_FRAME;
      if (event.frame === BLOCKED_FRAME) throw new Error(BLOCKED);
    });
    await ctx.tool.hook("execute.after", async (event) => {
      if (event.status === "completed") {
        const original = event.result;
        event.result = { content: BLOCKED };
        if (guard) event.result = await guard.tool(original) as typeof event.result;
      } else {
        const message = event.error.message;
        event.error = new ToolError({ message: BLOCKED });
        const clean = guard ? await guard.tool({ content: message }) as { content: string } : undefined;
        if (clean) event.error = new ToolError({ message: clean.content });
      }
    });

    let metrics: MetricsLease | undefined;
    if (config?.metricsPort !== undefined) {
      try {
        metrics = await acquireMetrics(config.metricsPort);
        console.info(`Vault Guard metrics: http://127.0.0.1:${metrics.port}/metrics`);
      } catch {
        // Metrics availability must not determine whether the content filter runs.
        console.error("Vault Guard: metrics listener unavailable; filtering remains active.");
      }
    }
    if (config) guard = new Guard(config, undefined, metrics?.metrics);
    return async () => {
      guard?.close();
      await metrics?.close();
    };
  },
});
