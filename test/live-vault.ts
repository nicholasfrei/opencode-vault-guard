// Explicit, opt-in integration test against an EXISTING local Vault cluster.
// Run: VAULT_GUARD_LIVE_APPROVED=1 node --import tsx test/live-vault.ts
// This creates one CAS0 fixture, one exact-path policy, and one short-lived token.
// No credential values or raw model request/response bodies are written to reports.
import { spawn, execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { homedir, tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { credentialFixtures } from "./fixtures/credentials.js";

// Reject before reading credential/configuration environment, installing cleanup
// handlers, contacting services, or creating/overwriting any evidence artifact.
if (process.env.VAULT_GUARD_LIVE_APPROVED !== "1") {
  console.error(JSON.stringify({ type: "harness-rejection", reason: "Explicit approval required: set VAULT_GUARD_LIVE_APPROVED=1", liveRunStarted: false, reportWritten: false }));
  process.exit(1);
}

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const binary = process.env.VAULT_GUARD_LIVE_OPENCODE ?? process.env.OPENCODE_BIN ?? "opencode";
const namespace = process.env.VAULT_GUARD_LIVE_NAMESPACE ?? "";
const mount = process.env.VAULT_GUARD_LIVE_MOUNT ?? "kv";
const vaultAddress = process.env.VAULT_ADDR ?? "http://127.0.0.1:8200";
const adminToken = process.env.VAULT_TOKEN;
const sharedURL = process.env.VAULT_GUARD_LIVE_SERVER;
const model = process.env.VAULT_GUARD_LIVE_MODEL ?? "";
const replacedPlugin = process.env.VAULT_GUARD_LIVE_REPLACED_PLUGIN ?? "opencode-secrets-protect";
const requiredPlugins = process.env.VAULT_GUARD_LIVE_REQUIRED_PLUGINS?.split(",").filter(Boolean) ?? [];
const marker = "[REDACTED]";
const runID = randomUUID();
const fixturePath = `vault-guard-trial/${runID}/fixture`;
const policyName = `vault-guard-trial-${runID}`;
const configDir = join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "opencode");
const originals = [process.env.VAULT_GUARD_LIVE_CONFIG_FILE ?? join(configDir, "opencode.json"), ...(process.env.VAULT_GUARD_LIVE_SNAPSHOT_FILES?.split(delimiter).filter(Boolean) ?? [])];
const tempParent = process.env.VAULT_GUARD_LIVE_TMPDIR ?? tmpdir();
const results: Record<string, any> = { date: new Date().toISOString(), vaultAddress, namespace, mount, model, cases: {}, cleanup: {}, limitations: [] };
const snapshots: { path: string; backup: string; hash: string; mode: number }[] = [];
let root = "";
let token = "";
let createdFixture = false;
let createdPolicy = false;
let liveRunStarted = false;
let revoked = false;
let failure = "";
let server: ReturnType<typeof createServer> | undefined;
let active: ReturnType<typeof spawn> | undefined;
let current: { file: string; grep: string; needles: string[]; bodies: number; markers: number; survivors: number; toolContinuations: number; shapes: string[][] } | undefined;
const interrupted = new AbortController();
let cleaningUp = false;
const onSignal = () => { interrupted.abort(); active?.kill("SIGTERM"); };
process.on("SIGINT", onSignal);
process.on("SIGTERM", onSignal);

class TrialFailure extends Error {}
function requireThat(value: unknown, message: string): asserts value { if (!value) throw new TrialFailure(message); }
function hash(bytes: Buffer) { return createHash("sha256").update(bytes).digest("hex"); }
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
// Project only validated primitive measurements into reports. An unexpected
// API/file shape must never cause a raw response or configuration to be logged.
function probeEvidence(value: unknown): Record<string, any> | undefined {
  if (!object(value)) return undefined;
  const result: Record<string, any> = {};
  for (const key of ["beforeHttp", "afterHttp", "responses", "responseSuccesses", "inputCanaries", "survivingCanaries", "markers", "toolMarkers", "toolErrors"]) {
    const count = value[key];
    if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 0) return undefined;
    result[key] = count;
  }
  for (const key of ["oldAbsent", "newActive", "realPluginsActive", "probeOrderCorrect", "authPreserved", "authPresent", "unexpectedTransport", "assertionFailed"]) {
    if (typeof value[key] !== "boolean") return undefined;
    result[key] = value[key];
  }
  for (const key of ["guardMs", "requestMs", "toolMs", "responseStatuses"]) {
    const measurements = value[key];
    if (!Array.isArray(measurements) || measurements.length > 100 || !measurements.every((n) => typeof n === "number" && Number.isFinite(n) && n >= 0)) return undefined;
    if (key === "responseStatuses" && !measurements.every((n) => Number.isInteger(n) && n >= 100 && n <= 599)) return undefined;
    result[key] = [...measurements];
  }
  if (!object(value.toolCalls)) return undefined;
  result.toolCalls = {};
  for (const [tool, count] of Object.entries(value.toolCalls)) {
    if (!["read", "shell", "grep", "guard_live_fixture"].includes(tool) || typeof count !== "number" || !Number.isSafeInteger(count) || count < 0) return undefined;
    result.toolCalls[tool] = count;
  }
  return result;
}
function strings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (value && typeof value === "object") return Object.entries(value).flatMap(([key, child]) => [key, ...strings(child)]);
  return [];
}
async function vault(path: string, method = "GET", data?: unknown, credential = adminToken!): Promise<{ status: number; body: any }> {
  const response = await fetch(`${vaultAddress}/v1/${path}`, {
    method, headers: { "X-Vault-Token": credential, ...(path === "sys/health" ? {} : { "X-Vault-Namespace": namespace }), "content-type": "application/json" },
    body: data === undefined ? undefined : JSON.stringify(data), redirect: "error",
    signal: cleaningUp ? AbortSignal.timeout(5000) : AbortSignal.any([interrupted.signal, AbortSignal.timeout(5000)]),
  });
  const body = response.status === 204 ? {} : await response.json();
  return { status: response.status, body };
}
function sharedInfo(): { version: string; pid: number } | undefined {
  if (!sharedURL) return undefined;
  try {
    const output = execFileSync(binary, ["api", "--server", sharedURL, "get", "/api/info"], { encoding: "utf8", timeout: 15000, stdio: ["ignore", "pipe", "pipe"] });
    const parsed: unknown = JSON.parse(output);
    if (!object(parsed)) return undefined;
    const info = parsed.data ?? parsed;
    if (!object(info) || typeof info.version !== "string" || !/^2\.0\.\d+$/.test(info.version) || typeof info.pid !== "number" || !Number.isSafeInteger(info.pid) || info.pid <= 0) return undefined;
    return { version: info.version, pid: info.pid };
  } catch { return undefined; }
}
async function run(name: string, config: Record<string, unknown>, prompt: string, expected: "positive" | "blocked", real = false) {
  requireThat(!interrupted.signal.aborted, "Trial interrupted");
  const directory = join(root, name);
  await mkdir(directory, { recursive: true });
  const evidence = join(directory, "evidence.json");
  const opts = { evidence, fixture: current!.file, grepFixture: current!.grep, needles: join(root, "needles.json"), real, fakeOrigin: `http://127.0.0.1:${(server!.address() as { port: number }).port}`, replacedPlugin, requiredPlugins };
  const plugins = [`-${replacedPlugin}`, { package: join(root, "before"), options: opts }, { package: repo, options: config }, { package: join(root, "after"), options: opts }];
  const rules = [
    { action: "*", resource: "*", effect: "deny" },
    { action: "read", resource: current!.file, effect: "allow" },
    { action: "external_directory", resource: `${root}/*`, effect: "allow" },
    { action: "grep", resource: "SYNTHETIC_CANARY", effect: "allow" },
    { action: "shell", resource: `cat -- '${current!.file}'`, effect: "allow" },
    { action: "shell", resource: `cat -- ${current!.file}`, effect: "allow" },
    { action: "guard_live_fixture", resource: "*", effect: "allow" },
  ];
  const configFile = {
    model: real ? model : "guard-live/guard-live", plugins, snapshots: false,
    enabled_providers: real ? ["github-copilot"] : ["github-copilot", "guard-live"],
    agents: { build: { system: "Perform only the requested synthetic validation. Never inspect other files or settings. Finish with LIVE_GUARD_OK after the requested tool work.", permissions: rules } },
    providers: real ? { "github-copilot": { settings: { transport: "http" } } } : {
      "guard-live": { name: "Local synthetic validation", env: ["GUARD_LIVE_FAKE_AUTH"], package: "@opencode/ai/providers/openai-compatible", settings: { baseURL: `http://127.0.0.1:${(server!.address() as { port: number }).port}/v1`, transport: "http" }, models: { "guard-live": { name: "Local synthetic validation", capabilities: { tools: true }, limit: { context: 128000, output: 1024 } } } },
    },
    policies: real ? [] : [{ action: "provider.use", resource: "*", effect: "deny" }, { action: "provider.use", resource: "guard-live", effect: "allow" }],
  };
  await writeFile(join(directory, "opencode.json"), JSON.stringify(configFile), { mode: 0o600 });
  const beforeRequests = current!.bodies;
  const start = performance.now();
  active = spawn(binary, ["run", "--standalone", "--auto", "--format", "json", "--title", "Vault Guard synthetic validation", "--model", real ? model : "guard-live/guard-live", prompt], {
    cwd: directory, env: { ...process.env, PWD: directory, XDG_CONFIG_HOME: join(root, "config"), GUARD_LIVE_FAKE_AUTH: "synthetic-local-auth", OPENCODE_LOG_LEVEL: "ERROR" }, stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  active.stdout!.on("data", (chunk) => { if (output.length < 2_000_000) output += String(chunk); });
  active.stderr!.on("data", (chunk) => { if (output.length < 2_000_000) output += String(chunk); });
  let timedOut = false;
  const child = active;
  const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); }, real ? 90000 : 60000);
  const hardTimer = setTimeout(() => child.kill("SIGKILL"), real ? 95000 : 65000);
  let code: number | null;
  try { code = await new Promise<number | null>((done, reject) => { child.once("exit", done); child.once("error", reject); }); }
  finally { clearTimeout(timer); clearTimeout(hardTimer); active = undefined; }
  let e: any = {};
  try { e = probeEvidence(JSON.parse(await readFile(evidence, "utf8"))) ?? {}; } catch { /* Invalid or missing evidence fails below; never log its contents. */ }
  const eventTypes: Record<string, number> = {};
  const errorTypes: string[] = [];
  let completion = false;
  for (const line of output.split("\n")) {
    try {
      const parsed = JSON.parse(line);
      const eventType = ["text", "reasoning", "tool_use", "step_start", "step_finish", "error"].includes(parsed.type) ? parsed.type : "other";
      eventTypes[eventType] = (eventTypes[eventType] ?? 0) + 1;
      if (parsed.type === "error") {
        const errorType = ["unknown", "provider.no-route", "provider.invalid-request", "provider.authentication", "provider.rate-limit", "provider.unavailable"].includes(parsed.error?.type) ? parsed.error.type : "other";
        errorTypes.push(errorType);
      }
      if (parsed.type !== "tool_use" && strings(parsed).some((s) => s.includes("LIVE_GUARD_OK")) && !strings(parsed).some((s) => s.includes("Perform only") || s.includes("Call guard_live_fixture"))) completion = true;
    } catch { /* Logs are inspected only for fixed failure classes, never persisted. */ }
  }
  const r = results.cases[name] = {
    exitCode: code, timedOut, elapsedMs: performance.now() - start,
    fakeRequests: current!.bodies - beforeRequests, completion, eventTypes, errorTypes,
    withheldError: output.includes("Content withheld because safe inspection could not be completed"),
    providerAuthFailure: /unauthori[sz]ed|authentication failed|HTTP 401|status.?401/i.test(output),
    providerRateLimited: /rate.limit|HTTP 429|status.?429/i.test(output),
    providerModelUnavailable: /model.not.found|model.*not supported|unknown model/i.test(output),
    providerError: /"type":"error"|ProviderError|provider.invalid-request|invalid_request_error/i.test(output),
    ...e,
  };
  requireThat(!timedOut, `${name}: runtime timed out`);
  requireThat(e.beforeHttp > 0 && e.oldAbsent && e.newActive && e.realPluginsActive && e.probeOrderCorrect, `${name}: runtime/plugin evidence missing`);
  requireThat(!e.assertionFailed && !e.unexpectedTransport, `${name}: probe assertion failed`);
  if (expected === "blocked") {
    requireThat(r.fakeRequests === 0 && e.afterHttp === 0 && r.withheldError && !completion, `${name}: explicit guard failure was not proved`);
  } else {
    requireThat(code === 0 && completion && e.afterHttp >= 2 && e.responses >= 2 && e.responseSuccesses === e.responses, `${name}: successful model/tool continuation missing`);
    requireThat(e.survivingCanaries === 0 && e.markers > 0 && e.toolMarkers > 0 && e.authPreserved && !e.toolErrors, `${name}: sanitization evidence missing`);
    const expectedTools = real ? ["guard_live_fixture"] : ["read", "shell", "grep", "guard_live_fixture"];
    requireThat(expectedTools.every((tool) => e.toolCalls[tool] === 1), `${name}: expected tool coverage missing`);
    if (real) requireThat(e.authPresent, `${name}: intentional provider auth missing`);
  }
  r.passed = true;
  console.log(JSON.stringify({ case: name, passed: true, requests: e.afterHttp, markers: e.markers, toolMarkers: e.toolMarkers, elapsedMs: Math.round(r.elapsedMs) }));
}

try {
  requireThat(adminToken && new URL(vaultAddress).hostname === "127.0.0.1", "Existing loopback Vault and inherited administrative credential required");
  requireThat(/^[A-Za-z0-9_/-]+$/.test(namespace) && /^[A-Za-z0-9_-]+$/.test(mount), "Explicit namespace and valid mount required for the trial");
  requireThat(/^github-copilot\/[A-Za-z0-9_.-]+$/.test(model), "Explicit VAULT_GUARD_LIVE_MODEL for Copilot is required");
  requireThat(/^[A-Za-z0-9_.-]+$/.test(replacedPlugin) && requiredPlugins.every((id) => /^[A-Za-z0-9_.-]+$/.test(id)), "Invalid plugin IDs");
  const version = execFileSync(binary, ["--version"], { encoding: "utf8" }).trim().match(/^opencode v(2\.0\.(\d+))$/);
  requireThat(version && Number(version[2]) >= 25, "Expected OpenCode 2.0.25 or later in the 2.0 series");
  results.runtime = version[1];
  const info = sharedInfo();
  if (sharedURL) {
    requireThat(info && info.version === version[1], "Configured shared OpenCode service unavailable or version differs");
    results.sharedPID = info.pid;
  }
  root = await mkdtemp(join(tempParent, "vault-guard-live-")); await chmod(root, 0o700);
  await mkdir(join(root, "backups"), { mode: 0o700 });
  for (const [index, path] of originals.entries()) {
    const bytes = await readFile(path); const mode = (await stat(path)).mode & 0o777;
    const backup = join(root, "backups", String(index));
    await copyFile(path, backup); await chmod(backup, mode);
    snapshots.push({ path, backup, hash: hash(bytes), mode });
  }
  // Global provider policies outrank project policy. Use a private copy that adds
  // only the loopback fixture provider; keep all real global plugin sources.
  // HOME/data/auth remain real, and the original files are never edited.
  const shadow = join(root, "config/opencode"); await mkdir(shadow, { recursive: true, mode: 0o700 });
  const globalConfig = JSON.parse(await readFile(originals[0]!, "utf8"));
  globalConfig.enabled_providers = [...new Set([...(globalConfig.enabled_providers ?? []), "guard-live"])];
  await writeFile(join(shadow, "opencode.json"), JSON.stringify(globalConfig), { mode: 0o600 });
  for (const folder of ["plugins", "skills"]) {
    if (await stat(join(configDir, folder)).then(() => true, () => false)) await symlink(join(configDir, folder), join(shadow, folder), "dir");
  }
  if (await stat(join(configDir, "AGENTS.md")).then(() => true, () => false)) await copyFile(join(configDir, "AGENTS.md"), join(shadow, "AGENTS.md"));
  const health = await vault("sys/health");
  requireThat(health.status === 200 && health.body.sealed === false, "Existing Vault not healthy");
  requireThat(typeof health.body.version === "string" && /^\d+\.\d+\.\d+(?:[+-][A-Za-z0-9.-]+)?$/.test(health.body.version), "Unexpected Vault health response");
  results.vaultVersion = health.body.version;
  const mounts = await vault("sys/mounts");
  const entries = mounts.body.data ?? mounts.body;
  requireThat(entries[`${mount}/`]?.type === "kv" && entries[`${mount}/`]?.options?.version === "2", "Existing KVv2 mount unavailable");
  const credential = `synthetic live inventory ${runID}`;
  const complex = `synthetic complex ${runID} /+"\\\n\u00ff>>>`;
  const known = [...new Set([credential, complex].flatMap((value) => [value, encodeURIComponent(value), Buffer.from(value).toString("base64"), Buffer.from(value).toString("base64url"), JSON.stringify(value).slice(1, -1)]))];
  const needles = [...known, ...credentialFixtures.map((f) => f.value)];
  results.coverage = { inventoryFields: 2, distinctKnownVariants: known.length, encodings: ["raw", "URI", "base64", "base64url", "JSON string escaping"], patternFamilies: credentialFixtures.map((f) => f.name) };
  await writeFile(join(root, "needles.json"), JSON.stringify(needles), { mode: 0o600 });
  liveRunStarted = true;
  const put = await vault(`${mount}/data/${fixturePath}`, "POST", { options: { cas: 0 }, data: { credential, complex } });
  requireThat(put.status === 200 && put.body.data?.version === 1, "CAS0 fixture creation failed"); createdFixture = true;
  const policy = await vault(`sys/policies/acl/${policyName}`, "PUT", { policy: `path "${mount}/data/${fixturePath}" { capabilities = ["read"] }` });
  requireThat(policy.status === 204, "Exact-path temporary policy creation failed"); createdPolicy = true;
  const issued = await vault("auth/token/create", "POST", { policies: [policyName], no_default_policy: true, ttl: "10m", explicit_max_ttl: "10m", renewable: false, display_name: "vault-guard-live-trial" });
  requireThat(issued.status === 200 && typeof issued.body.auth?.client_token === "string" && issued.body.auth.client_token.length > 0, "Trial child token creation failed");
  token = issued.body.auth.client_token;
  requireThat(typeof issued.body.auth.renewable === "boolean" && typeof issued.body.auth.lease_duration === "number" && Number.isSafeInteger(issued.body.auth.lease_duration) && issued.body.auth.lease_duration > 0 && Array.isArray(issued.body.auth.policies) && issued.body.auth.policies.every((value: unknown) => typeof value === "string"), "Unexpected child token response");
  results.token = { renewable: issued.body.auth.renewable, ttlSeconds: issued.body.auth.lease_duration, noDefaultPolicy: !issued.body.auth.policies.includes("default"), exactPolicyOnly: issued.body.auth.policies.length === 1 && issued.body.auth.policies[0] === policyName };
  requireThat(results.token.renewable === false && results.token.noDefaultPolicy && results.token.exactPolicyOnly, "Child token constraints not satisfied");
  const tokenFile = join(root, "reader-token"); await writeFile(tokenFile, token, { mode: 0o600 });
  const read = await vault(`${mount}/data/${fixturePath}`, "GET", undefined, token);
  requireThat(read.status === 200 && read.body.data?.data?.credential === credential, "Read-only token cannot read fixture");
  // Ask the administrative capabilities endpoint about the child without mutating Vault.
  const childCaps = await vault("sys/capabilities", "POST", { token, paths: [`${mount}/data/${fixturePath}`, `${mount}/data/${fixturePath}-outside`] });
  results.childScopeVerified = childCaps.status === 200 && JSON.stringify(childCaps.body.data?.[`${mount}/data/${fixturePath}`]) === '["read"]' && JSON.stringify(childCaps.body.data?.[`${mount}/data/${fixturePath}-outside`]) === '["deny"]';
  requireThat(results.childScopeVerified, "Child token exact read-only scope not proved");
  for (const position of ["before", "after"]) {
    const directory = join(root, position); await mkdir(directory);
    await writeFile(join(directory, "package.json"), JSON.stringify({ type: "module", exports: "./index.ts" }));
    await writeFile(join(directory, "index.ts"), `export { ${position} as default } from ${JSON.stringify(join(repo, "test/live-probe.ts"))};\n`);
  }
  server = createServer(async (request, response) => {
    try {
      requireThat(current, "No active fake provider case");
      let raw = ""; for await (const chunk of request) raw += chunk.toString();
      const body = JSON.parse(raw); const text = strings(body);
      current.bodies++; current.markers += text.reduce((n, s) => n + s.split(marker).length - 1, 0);
      current.survivors += current.needles.filter((n) => text.some((s) => s.includes(n))).length;
      requireThat(current.survivors === 0, "Canary reached fake provider");
      const tools: string[] = (body.tools ?? []).map((t: any) => t.function?.name).filter(Boolean);
      current.shapes.push(tools);
      const messages = body.messages ?? [];
      const completed = messages.filter((m: any) => m.role === "tool").length;
      if (completed) current.toolContinuations++;
      const steps = [
        { tool: "read", input: { path: current.file } },
        { tool: "shell", input: { command: `cat -- '${current.file}'` } },
        { tool: "grep", input: { pattern: "SYNTHETIC_CANARY", path: current.grep, literal: true } },
        { tool: "guard_live_fixture", input: {} },
      ];
      const step = tools.length ? steps[completed] : undefined;
      const name = step && tools.find((n) => n === step.tool || n.endsWith(`_${step.tool}`));
      if (step) requireThat(name, "Requested direct tool absent from model tool schema");
      const delta = step ? { role: "assistant", tool_calls: [{ index: 0, id: `trial_${completed}`, type: "function", function: { name, arguments: JSON.stringify(step.input) } }] } : { role: "assistant", content: "LIVE_GUARD_OK" };
      const finish = step ? "tool_calls" : "stop";
      if (body.stream) {
        response.writeHead(200, { "content-type": "text/event-stream" });
        response.write(`data: ${JSON.stringify({ id: "live-trial", object: "chat.completion.chunk", created: 1, model: "guard-live", choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
        response.write(`data: ${JSON.stringify({ id: "live-trial", object: "chat.completion.chunk", created: 1, model: "guard-live", choices: [{ index: 0, delta: {}, finish_reason: finish }] })}\n\n`);
        response.end("data: [DONE]\n\n");
      } else {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ id: "live-trial", object: "chat.completion", created: 1, model: "guard-live", choices: [{ index: 0, message: delta, finish_reason: finish }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }));
      }
    } catch { response.writeHead(500, { "content-type": "application/json" }); response.end('{"error":{"message":"Local trial assertion failed"}}'); }
  });
  await new Promise<void>((done) => server!.listen(0, "127.0.0.1", done));
  const config = { mode: "redact", patterns: false, entropy: false, vault: { address: vaultAddress, namespace, tokenFile, secrets: [{ mount, path: fixturePath, fields: ["credential", "complex"] }], refreshMs: 60000, timeoutMs: 3000 } };
  for (const patterns of [false, true]) {
    const name = patterns ? "patterns" : "inventory";
    const file = join(root, `${name}.txt`); const grep = join(root, `${name}-grep.txt`);
    const values = [...known, ...(patterns ? credentialFixtures.map((f) => f.value) : [])];
    await writeFile(file, values.map((v, i) => `SYNTHETIC_CANARY ${i} ${v}`).join("\n"), { mode: 0o600 });
    await writeFile(grep, [credential, ...(patterns ? credentialFixtures.map((f) => f.value) : [])].map((v, i) => `SYNTHETIC_CANARY ${i} ${v}`).join("\n"), { mode: 0o600 });
    current = { file, grep, needles, bodies: 0, markers: 0, survivors: 0, toolContinuations: 0, shapes: [] };
    await run(name, { ...config, patterns }, `Perform the four synthetic fixture tool calls requested by the local test provider. Synthetic samples:\n${values.join("\n")}`, "positive");
    results.cases[name].fakeProvider = { requests: current.bodies, markers: current.markers, survivors: current.survivors, toolContinuations: current.toolContinuations, toolSchemas: current.shapes };
    requireThat(current.bodies === 5 && current.toolContinuations === 4 && current.markers > 0 && current.survivors === 0, `${name}: fake socket evidence missing`);
  }
  const prompt = `Synthetic input: ${credential}`;
  await run("block", { ...config, mode: "block" }, prompt, "blocked");
  await run("missing-vault-config", { patterns: false, vault: { address: vaultAddress } }, prompt, "blocked");
  await run("invalid-config", { ...config, mode: "invalid" }, prompt, "blocked");
  await run("missing-token-file", { ...config, vault: { ...config.vault, tokenFile: join(root, "absent-token") } }, prompt, "blocked");
  results.preflightPassed = true;
  // One child token is authorized; its destructive revocation test must run AFTER the live trial.
  let providerFailure: unknown;
  try {
    await run("copilot", { ...config, patterns: true }, `Call guard_live_fixture exactly once, then respond with exactly LIVE_GUARD_OK. Do not repeat fixture data. Synthetic samples:\n${known.join("\n")}\n${credentialFixtures.map((f) => f.value).join("\n")}`, "positive", true);
  } catch (error) { providerFailure = error; }
  const revoke = await vault("auth/token/revoke", "POST", { token });
  requireThat(revoke.status === 204, "Trial token revocation failed"); revoked = true;
  await run("revoked-token", config, prompt, "blocked");
  if (providerFailure) throw providerFailure;
  results.passed = true;
} catch (error) {
  // Only our fixed assertion messages may enter artifacts. OS, provider, parse,
  // and Vault exceptions can contain credentials and must never be serialized.
  failure = error instanceof TrialFailure ? error.message : "Live trial failed; private error details withheld";
  results.passed = false; results.failure = failure;
} finally {
  cleaningUp = true;
  if (active && active.exitCode === null) active.kill("SIGTERM");
  results.cleanup.trialProcessesStopped = !active || active.exitCode !== null;
  server?.closeAllConnections(); server?.close();
  if (token && !revoked) {
    try { revoked = (await vault("auth/token/revoke", "POST", { token })).status === 204; } catch { /* Report false below. */ }
  }
  results.cleanup.tokenRevoked = token ? revoked : true;
  if (token) {
    try { results.cleanup.tokenRejected = [403, 400].includes((await vault(`${mount}/data/${fixturePath}`, "GET", undefined, token)).status); } catch { results.cleanup.tokenRejected = false; }
  } else results.cleanup.tokenRejected = true;
  if (createdFixture) {
    try {
      results.cleanup.fixtureDeleted = (await vault(`${mount}/metadata/${fixturePath}`, "DELETE")).status === 204;
      results.cleanup.fixtureAbsent = (await vault(`${mount}/metadata/${fixturePath}`)).status === 404;
    } catch { results.cleanup.fixtureDeleted = false; results.cleanup.fixtureAbsent = false; }
  } else { results.cleanup.fixtureDeleted = true; results.cleanup.fixtureAbsent = true; }
  if (createdPolicy) {
    try {
      results.cleanup.policyDeleted = (await vault(`sys/policies/acl/${policyName}`, "DELETE")).status === 204;
      results.cleanup.policyAbsent = (await vault(`sys/policies/acl/${policyName}`)).status === 404;
    } catch { results.cleanup.policyDeleted = false; results.cleanup.policyAbsent = false; }
  } else { results.cleanup.policyDeleted = true; results.cleanup.policyAbsent = true; }
  results.cleanup.originalBytesMatch = true; results.cleanup.originalModesMatch = true; results.cleanup.backupBytesMatch = true;
  for (const snapshot of snapshots) {
    try {
      results.cleanup.originalBytesMatch &&= hash(await readFile(snapshot.path)) === snapshot.hash;
      results.cleanup.originalModesMatch &&= ((await stat(snapshot.path)).mode & 0o777) === snapshot.mode;
      results.cleanup.backupBytesMatch &&= hash(await readFile(snapshot.backup)) === snapshot.hash;
    } catch { results.cleanup.originalBytesMatch = false; results.cleanup.originalModesMatch = false; }
  }
  results.cleanup.configFilesVerified = snapshots.length;
  // No baseline means startup failed before a live service check completed.
  // In particular, rejection paths must not introduce a service read in finally.
  const info = typeof results.sharedPID === "number" ? sharedInfo() : undefined;
  results.cleanup.sharedServerAvailable = !sharedURL || info?.version === results.runtime;
  results.cleanup.sharedPIDUnchanged = !sharedURL || info?.pid === results.sharedPID;
  if (root) { await rm(root, { recursive: true, force: true }); results.cleanup.temporaryFilesRemoved = true; }
  results.cleanup.all = Object.entries(results.cleanup).every(([k, v]) => k === "configFilesVerified" ? v === originals.length : v === true);
  if (!results.cleanup.all) results.passed = false;
  let reportWritten = false;
  if (liveRunStarted) {
    await mkdir(join(repo, "docs"), { recursive: true });
    // Only a successful live invocation may replace the canonical evidence.
    // Failed live attempts get distinct artifacts; preflight rejection gets none.
    const report = join(repo, results.passed ? "docs/live-vault-results.json" : `docs/live-vault-attempt-${runID}.json`);
    const temporary = `${report}.${runID}.tmp`;
    try {
      await writeFile(temporary, JSON.stringify(results, null, 2) + "\n", { mode: 0o600 });
      await rename(temporary, report);
      reportWritten = true;
    } finally { await rm(temporary, { force: true }); }
  }
  console.log(JSON.stringify({ type: liveRunStarted ? "live-validation" : "harness-rejection", liveRunStarted, reportWritten, passed: results.passed, failure: results.failure, cleanup: results.cleanup }));
  process.off("SIGINT", onSignal);
  process.off("SIGTERM", onSignal);
}
if (!results.passed) process.exitCode = 1;
