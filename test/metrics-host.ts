// Verify aggregation across two real OpenCode locations in one isolated server.
// Uses synthetic credentials and a loopback model; no Vault or hosted provider calls.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { Service } from "@opencode/client/service";
import { REDACTED } from "../src/scanner.js";

const root = await mkdtemp(join(tmpdir(), "vault-guard-metrics-host-"));
const binary = process.env.OPENCODE_BIN ?? "opencode";
const children: ChildProcess[] = [];
const servers: Server[] = [];
const env = {
  PATH: process.env.PATH, HOME: join(root, "home"), TMPDIR: root,
  XDG_CONFIG_HOME: join(root, "config"), XDG_DATA_HOME: join(root, "data"),
  XDG_CACHE_HOME: join(root, "cache"), XDG_STATE_HOME: join(root, "state"),
  METRICS_FIXTURE_KEY: "synthetic-provider-auth", NO_COLOR: "1",
};
const canary = "ghp_" + "a".repeat(36);
let requests = 0;
let survivors = 0;
let redactedRequests = 0;

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return address.port;
}

async function reservePort(): Promise<number> {
  const server = createServer();
  const port = await listen(server);
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function start(args: string[], cwd: string): ChildProcess {
  const child = spawn(binary, args, { cwd, env, stdio: "ignore" });
  children.push(child);
  return child;
}

async function run(args: string[], cwd: string): Promise<void> {
  const child = start(args, cwd);
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); }, 20_000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("exit", resolve);
      child.once("error", reject);
    });
    assert.equal(timedOut, false, "OpenCode request timed out");
    assert.equal(code, 0, "OpenCode request failed");
  } finally { clearTimeout(timer); }
}

function sample(text: string, metric: string): number {
  const line = text.split("\n").find((line) => line.startsWith(metric + " "));
  assert.ok(line, "Expected metrics sample missing");
  return Number(line.slice(metric.length + 1));
}

try {
  await mkdir(env.HOME, { recursive: true });
  const metricsPort = await reservePort();
  const servicePort = await reservePort();
  const serviceURL = `http://127.0.0.1:${servicePort}`;
  const model = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk.toString();
    requests++;
    if (body.includes(canary)) survivors++;
    if (body.includes(REDACTED)) redactedRequests++;
    const parsed = JSON.parse(body) as { stream?: boolean };
    const base = { id: "fixture", created: 1, model: "fixture" };
    if (parsed.stream) {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write(`data: ${JSON.stringify({ ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "OK" }, finish_reason: null }] })}\n\n`);
      response.write(`data: ${JSON.stringify({ ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`);
      response.end("data: [DONE]\n\n");
    } else {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ...base, object: "chat.completion", choices: [{ index: 0, message: { role: "assistant", content: "OK" }, finish_reason: "stop" }] }));
    }
  });
  servers.push(model);
  const modelPort = await listen(model);
  const config = {
    model: "metrics-fixture/fixture",
    plugins: [{ package: resolve("."), options: { metricsPort } }],
    policies: [{ action: "provider.use", resource: "*", effect: "deny" }, { action: "provider.use", resource: "metrics-fixture", effect: "allow" }],
    providers: { "metrics-fixture": {
      env: ["METRICS_FIXTURE_KEY"], package: "@opencode/ai/providers/openai-compatible",
      settings: { baseURL: `http://127.0.0.1:${modelPort}/v1` },
      models: { fixture: { name: "Local fixture", limit: { context: 128000, output: 128 } } },
    } },
  };
  const locations = [join(root, "first"), join(root, "second")];
  for (const directory of locations) {
    await mkdir(directory);
    await writeFile(join(directory, "opencode.json"), JSON.stringify(config));
  }
  const service = start(["serve", "--service", "--hostname", "127.0.0.1", "--port", String(servicePort)], root);
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const endpoint = await Service.discover({ file: join(env.XDG_STATE_HOME, "opencode", "service.json") });
      ready = endpoint?.url === serviceURL;
    } catch { /* Starting. */ }
    if (ready || service.exitCode !== null) break;
    await delay(50);
  }
  assert.ok(ready, `Isolated OpenCode server did not become ready (exit ${service.exitCode})`);
  let previousScans = 0;
  let previousRedactions = 0;
  for (const [index, directory] of locations.entries()) {
    await run(["run", "--format", "json", `Do not use tools. Reply OK. Synthetic canary: ${canary}`], directory);
    const response = await fetch(`http://127.0.0.1:${metricsPort}/metrics`);
    assert.equal(response.status, 200);
    const text = await response.text();
    const scans = sample(text, 'vault_guard_scans_total{surface="http"}');
    const redactions = sample(text, 'vault_guard_secret_matches_prevented_total{surface="http",action="redact",detector="pattern"}');
    assert.ok(scans > previousScans, "Second location did not contribute scans");
    assert.ok(redactions > previousRedactions, "Second location did not contribute redactions");
    assert.equal(sample(text, "vault_guard_active_instances"), index + 1);
    previousScans = scans;
    previousRedactions = redactions;
  }
  assert.equal(survivors, 0, "Synthetic canary reached the fake provider");
  assert.ok(redactedRequests >= 2);
  console.log(JSON.stringify({ passed: true, locations: 2, requests, redactedRequests, survivingCanaries: survivors, sharedMetricRedactions: previousRedactions }));
} finally {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      child.kill("SIGTERM");
      await Promise.race([exited, delay(3000)]);
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
  }
  for (const server of servers) { server.closeAllConnections(); server.close(); }
  await rm(root, { recursive: true, force: true });
}
