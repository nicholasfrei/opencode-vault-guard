import assert from "node:assert/strict";
import { test } from "node:test";
import plugin from "../src/index.js";
import { Error as ToolError } from "@opencode/plugin/promise/tool";
import { BLOCKED, BLOCKED_FRAME } from "../src/guard.js";
import { REDACTED } from "../src/scanner.js";

test("the plugin registers both egress transports and sanitizes successful and failed tools", async () => {
  const hooks = new Map<string, (event: any) => Promise<void>>();
  const hook = async (name: string, callback: (event: any) => Promise<void>) => { hooks.set(name, callback); return { dispose: async () => {} }; };
  const context = { options: {}, session: { hook }, tool: { hook } } as unknown as Parameters<typeof plugin.setup>[0];
  const cleanup = await plugin.setup(context);
  assert.deepEqual([...hooks.keys()], ["http.request", "experimental.ws.send", "execute.after"]);
  const token = "ghp_" + "Z7".repeat(18);
  const completed = { status: "completed", result: { content: token, metadata: { value: token } } };
  await hooks.get("execute.after")!(completed);
  assert.equal(completed.result.content, REDACTED);
  assert.equal(completed.result.metadata.value, REDACTED);
  const failed = { status: "error", error: new ToolError({ message: `failed with ${token}`, error: token, metadata: { token } }) };
  await hooks.get("execute.after")!(failed);
  assert.equal(failed.error.message, `failed with ${REDACTED}`);
  assert.equal(failed.error.error, undefined);
  assert.equal(failed.error.metadata, undefined);
  assert.equal(JSON.stringify(failed.error).includes(token), false);
  if (typeof cleanup === "function") await cleanup();
});

test("invalid plugin configuration still installs guards instead of leaving an unprotected session", async () => {
  const hooks = new Map<string, (event: any) => Promise<void>>();
  const hook = async (name: string, callback: (event: any) => Promise<void>) => { hooks.set(name, callback); return { dispose: async () => {} }; };
  const context = { options: { mode: "typo" }, session: { hook }, tool: { hook } } as unknown as Parameters<typeof plugin.setup>[0];
  const cleanup = await plugin.setup(context);
  const http = { request: new Request("https://provider.example.com", { method: "POST", body: "unsafe" }) };
  await assert.rejects(hooks.get("http.request")!(http), { message: BLOCKED });
  assert.equal(http.request.signal.aborted, true);
  const ws = { frame: "unsafe" };
  await assert.rejects(hooks.get("experimental.ws.send")!(ws), { message: BLOCKED });
  assert.equal(ws.frame, BLOCKED_FRAME);
  const tool = { status: "completed", result: { content: "unsafe" } };
  await hooks.get("execute.after")!(tool);
  assert.equal(tool.result.content, BLOCKED);
  if (typeof cleanup === "function") await cleanup();
});
