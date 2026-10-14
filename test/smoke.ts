// Exercises the built plugin inside an isolated OpenCode process with a real local Vault
// and a fake LLM endpoint. Only synthetic credentials are used; no hosted LLM is called.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { REDACTED } from "../src/scanner.js";

const root = await mkdtemp(join(tmpdir(), "vault-guard-smoke-"));
const secret = "synthetic-guard-canary-" + randomUUID();
const rootToken = randomUUID();
const children: ChildProcess[] = [];
const servers: Server[] = [];
const env: NodeJS.ProcessEnv = {
  PATH: process.env.PATH,
  HOME: join(root, "home"),
  XDG_CONFIG_HOME: join(root, "config"),
  XDG_DATA_HOME: join(root, "data"),
  XDG_CACHE_HOME: join(root, "cache"),
  XDG_STATE_HOME: join(root, "state"),
  TMPDIR: root,
  NO_COLOR: "1",
  GUARD_FAKE_PROVIDER_KEY: "synthetic-provider-auth",
  VAULT_LICENSE: process.env.VAULT_LICENSE,
  VAULT_LICENSE_PATH: process.env.VAULT_LICENSE_PATH,
};

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return address.port;
}

async function vaultRequest(address: string, path: string, body?: unknown): Promise<Record<string, any>> {
  const response = await fetch(`${address}/v1/${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-Vault-Token": rootToken, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  assert.ok(response.ok, "local Vault fixture request failed");
  return response.status === 204 ? {} : await response.json() as Record<string, any>;
}

async function runOpenCode(): Promise<{ code: number | null; output: string }> {
  const child = spawn("opencode", ["run", "--standalone", "--auto", "--format", "json", `Call guard_fixture once. Synthetic credential: ${secret}`], { cwd: join(root, "project"), env, stdio: ["ignore", "pipe", "pipe"] });
  children.push(child);
  let output = "";
  child.stdout!.on("data", (chunk) => { output += chunk.toString(); });
  child.stderr!.on("data", (chunk) => { output += chunk.toString(); });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); }, 15_000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => { child.once("exit", resolve); child.once("error", reject); });
    if (timedOut) {
      await writeFile(join(root, "diagnostic.txt"), output, { mode: 0o600 });
      throw new Error(`OpenCode invocation timed out; diagnostics: ${root}/diagnostic.txt`);
    }
    return { code, output };
  } finally {
    clearTimeout(timer);
  }
}

try {
  for (const path of [env.HOME!, env.XDG_CONFIG_HOME!, join(root, "project")]) await mkdir(path, { recursive: true });
  const reserve = createServer();
  const vaultPort = await listen(reserve);
  await new Promise<void>((resolve) => reserve.close(() => resolve()));
  const vaultAddress = `http://127.0.0.1:${vaultPort}`;
  const vault = spawn(process.env.VAULT_GUARD_TEST_VAULT ?? "vault", ["server", "-dev", `-dev-listen-address=127.0.0.1:${vaultPort}`, `-dev-root-token-id=${rootToken}`], { env, stdio: ["ignore", "pipe", "pipe"] });
  let vaultLog = "";
  vault.stdout!.on("data", (chunk) => { vaultLog += chunk.toString(); });
  vault.stderr!.on("data", (chunk) => { vaultLog += chunk.toString(); });
  children.push(vault);
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try {
      ready = (await fetch(`${vaultAddress}/v1/sys/health`, { signal: AbortSignal.timeout(200) })).ok;
      if (ready) break;
    } catch { /* The fixture is still starting. */ }
    await delay(100);
  }
  if (!ready) {
    await writeFile(join(root, "vault-diagnostic.txt"), vaultLog.replaceAll(rootToken, "[synthetic token]"), { mode: 0o600 });
    throw new Error(`isolated Vault dev server did not start; diagnostics: ${root}/vault-diagnostic.txt`);
  }
  await vaultRequest(vaultAddress, "secret/data/guard-fixture", { data: { credential: secret } });
  await vaultRequest(vaultAddress, "sys/policies/acl/guard-reader", { policy: 'path "secret/data/guard-fixture" { capabilities = ["read"] }' });
  const token = await vaultRequest(vaultAddress, "auth/token/create", { policies: ["guard-reader"], no_default_policy: true, ttl: "5m" });
  env.VAULT_GUARD_TOKEN = token.auth.client_token;

  const bodies: string[] = [];
  let sawToolResult = false;
  const upstream = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk.toString();
    bodies.push(body);
    const parsed = JSON.parse(body);
    const messages = parsed.messages ?? [];
    const toolName = parsed.tools?.find((tool: any) => tool.function?.name?.endsWith("guard_fixture"))?.function.name;
    const isAgent = Boolean(toolName);
    const hasToolResult = messages.some((message: any) => message.role === "tool");
    if (isAgent && hasToolResult) sawToolResult = true;
    const toolCall = isAgent && !hasToolResult;
    const delta = toolCall
      ? { role: "assistant", tool_calls: [{ index: 0, id: "call_fixture", type: "function", function: { name: toolName, arguments: "{}" } }] }
      : { role: "assistant", content: "vault guard smoke passed" };
    if (parsed.stream) {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write(`data: ${JSON.stringify({ id: "smoke", object: "chat.completion.chunk", created: 1, model: "guard-test", choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
      response.write(`data: ${JSON.stringify({ id: "smoke", object: "chat.completion.chunk", created: 1, model: "guard-test", choices: [{ index: 0, delta: {}, finish_reason: toolCall ? "tool_calls" : "stop" }] })}\n\n`);
      response.end("data: [DONE]\n\n");
    } else {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: "smoke", object: "chat.completion", created: 1, model: "guard-test", choices: [{ index: 0, message: delta, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }));
    }
  });
  servers.push(upstream);
  const upstreamPort = await listen(upstream);
  const fixture = join(root, "fixture");
  await mkdir(fixture);
  await writeFile(join(fixture, "package.json"), JSON.stringify({ name: "guard-fixture", type: "module", exports: "./index.ts" }));
  await writeFile(join(fixture, "index.ts"), `import { Plugin } from "@opencode/plugin";
export default Plugin.define({ id: "guard.fixture", async setup(ctx) {
  await ctx.tool.transform((editor) => editor.add({ name: "guard_fixture", description: "Return a synthetic test credential", input: { type: "object", properties: {} }, options: { codemode: false }, execute: async () => ({ content: ${JSON.stringify(secret)} }) }));
}});\n`);
  const config = {
    model: "guard-test/guard-test",
    plugins: [fixture, { package: resolve(process.env.VAULT_GUARD_TEST_PLUGIN ?? "."), options: { mode: "redact", patterns: false, metricsPort: 0, vault: { address: vaultAddress, tokenEnv: "VAULT_GUARD_TOKEN", secrets: [{ mount: "secret", path: "guard-fixture", fields: ["credential"] }] } } }],
    policies: [{ action: "provider.use", resource: "*", effect: "deny" }, { action: "provider.use", resource: "guard-test", effect: "allow" }],
    providers: { "guard-test": { name: "Local guard smoke fixture", env: ["GUARD_FAKE_PROVIDER_KEY"], package: "@opencode/ai/providers/openai-compatible", settings: { baseURL: `http://127.0.0.1:${upstreamPort}/v1` }, models: { "guard-test": { name: "Local fixture", capabilities: { tools: true }, limit: { context: 128000, output: 1024 } } } } },
  };
  await writeFile(join(root, "project", "opencode.json"), JSON.stringify(config));
  const { code, output } = await runOpenCode();
  if (code !== 0 || bodies.length === 0 || !sawToolResult) {
    console.log("Fixture request shapes:", bodies.map((body) => {
      const parsed = JSON.parse(body);
      return { roles: parsed.messages?.map((message: any) => message.role), tools: parsed.tools?.map((tool: any) => tool.function?.name) };
    }));
    // Diagnostics stay local and contain only synthetic fixture data.
    await writeFile(join(root, "diagnostic.txt"), output, { mode: 0o600 });
    throw new Error(`OpenCode smoke failed (exit=${code}, requests=${bodies.length}, toolResult=${sawToolResult}); diagnostics: ${root}/diagnostic.txt`);
  }
  assert.equal(bodies.some((body) => body.includes(secret)), false, "synthetic credential reached the fake provider");
  assert.ok(bodies.some((body) => body.includes(REDACTED)), "no redaction marker reached the fake provider");
  const guarded = config.plugins[1];
  assert.ok(guarded && typeof guarded === "object");
  for (const mode of ["block", "unavailable", "invalid"]) {
    guarded.options.mode = mode === "invalid" ? "invalid" : mode === "block" ? "block" : "redact";
    if (mode === "unavailable") await vaultRequest(vaultAddress, "auth/token/revoke", { token: env.VAULT_GUARD_TOKEN });
    await writeFile(join(root, "project", "opencode.json"), JSON.stringify(config));
    const before = bodies.length;
    const blocked = await runOpenCode();
    assert.notEqual(blocked.code, null, `${mode} request timed out instead of failing promptly`);
    assert.equal(bodies.length, before, `${mode} protection allowed a provider request`);
  }
  console.log(`PASS: real Vault KV v2 + installed OpenCode + built plugin; ${bodies.length} local model requests, prompt and tool output sanitized; block mode, revoked token, and invalid config withheld all requests.`);
} finally {
  for (const child of children) {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([new Promise<void>((resolve) => child.once("exit", () => resolve())), delay(3000)]);
      if (child.exitCode === null) child.kill("SIGKILL");
    }
  }
  for (const server of servers) { server.closeAllConnections(); server.close(); }
}
await rm(root, { recursive: true, force: true });
