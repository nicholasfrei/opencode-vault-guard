import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig } from "../src/config.js";
import { Inventory } from "../src/inventory.js";

const options = {
  vault: { address: "https://vault.example.com", namespace: "team/dev", secrets: [{ mount: "kv", path: "app/dev", fields: ["password"] }], refreshMs: 1000 },
};

test("Vault requests are scoped, authenticated, cached, and shared across concurrent scans", async () => {
  let calls = 0;
  const request: typeof fetch = async (url, init) => {
    calls++;
    assert.equal(String(url), "https://vault.example.com/v1/kv/data/app/dev");
    assert.equal(new Headers(init?.headers).get("X-Vault-Namespace"), "team/dev");
    assert.equal(new Headers(init?.headers).get("X-Vault-Token"), "fixture-token");
    assert.equal(init?.redirect, "error");
    assert.ok(init?.signal);
    return Response.json({ data: { data: { password: "fixture-password", ignored: "unselected-field" } } });
  };
  const inventory = new Inventory(parseConfig(options, {}), { VAULT_TOKEN: "fixture-token" }, request);
  const results = await Promise.all([inventory.values(), inventory.values(), inventory.values()]);
  assert.deepEqual(results[0], ["fixture-token", "fixture-password"]);
  assert.equal(calls, 1);
  await inventory.values();
  assert.equal(calls, 1);
  inventory.close();
});

test("refresh retains observed versions and refuses stale inventory when Vault becomes unavailable", async () => {
  let now = 100;
  let version = "fixture-first";
  let failed = false;
  const inventory = new Inventory(parseConfig(options, {}), { VAULT_TOKEN: "fixture-token" }, async () => {
    if (failed) return new Response("sensitive upstream diagnostic", { status: 403 });
    return Response.json({ data: { data: { password: version } } });
  }, () => now);
  await inventory.values();
  now += 1001;
  version = "fixture-second";
  assert.deepEqual(await inventory.values(), ["fixture-token", "fixture-first", "fixture-second"]);
  now += 1001;
  failed = true;
  await assert.rejects(inventory.values(), { message: "Vault Guard blocked content (inventory)." });
  failed = false;
  assert.ok((await inventory.values()).includes(version));
  inventory.close();
});

test("a missing selected field fails the entire inventory without publishing a partial refresh", async () => {
  const config = parseConfig({ vault: { ...options.vault, secrets: [{ mount: "kv", path: "app", fields: ["password", "missing"] }] } }, {});
  const inventory = new Inventory(config, { VAULT_TOKEN: "fixture-token" }, async () => Response.json({ data: { data: { password: "fixture-password" } } }));
  await assert.rejects(inventory.values(), /inventory/);
  inventory.close();
});

test("rotating a Vault Agent token file is observed on refresh", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "vault-guard-token-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tokenFile = join(directory, "token");
  await writeFile(tokenFile, "fixture-first-token", { mode: 0o600 });
  let now = 100;
  const tokens: string[] = [];
  const config = parseConfig({ vault: { ...options.vault, tokenFile } }, {});
  const inventory = new Inventory(config, {}, async (_url, init) => {
    tokens.push(new Headers(init?.headers).get("X-Vault-Token")!);
    return Response.json({ data: { data: { password: "fixture-password" } } });
  }, () => now);
  await inventory.values();
  await writeFile(tokenFile, "fixture-next-token");
  now += 1001;
  await inventory.values();
  assert.deepEqual(tokens, ["fixture-first-token", "fixture-next-token"]);
  inventory.close();
});

test("configured environment values are required and disposal prevents reuse", async () => {
  const config = parseConfig({ env: ["GUARD_TEST_SECRET"] }, {});
  await assert.rejects(new Inventory(config, {}).values(), /inventory/);
  const inventory = new Inventory(config, { GUARD_TEST_SECRET: "fixture-value" });
  assert.deepEqual(await inventory.values(), ["fixture-value"]);
  inventory.close();
  await assert.rejects(inventory.values(), /inventory/);
});

test("unsafe addresses, traversal paths, unknown options, and empty detection are rejected", () => {
  for (const config of [
    { typo: true },
    { patterns: false },
    { metricsPort: -1 },
    { env: ["BAD-NAME"] },
    { vault: { ...options.vault, address: "http://vault.example.com" } },
    { vault: { ...options.vault, address: "https://user:pass@vault.example.com" } },
    { vault: { ...options.vault, secrets: [{ mount: "kv", path: "../sys", fields: ["password"] }] } },
  ]) assert.throws(() => parseConfig(config, {}), /invalid configuration/);
});
