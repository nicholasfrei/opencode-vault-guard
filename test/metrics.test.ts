import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { acquireMetrics, Metrics } from "../src/metrics.js";

test("new registries expose zero scan counters before their first operation", () => {
  const text = new Metrics().render();
  for (const surface of ["http", "websocket", "tool"]) {
    assert.ok(text.includes(`vault_guard_scans_total{surface="${surface}"} 0`));
  }
});

test("concurrent plugin instances share a fixed-port listener and survive independent unloads", async (t) => {
  const reservation = createServer();
  await new Promise<void>((resolve) => reservation.listen(0, "127.0.0.1", resolve));
  const address = reservation.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve) => reservation.close(() => resolve()));
  const [first, second] = await Promise.all([acquireMetrics(port), acquireMetrics(port)]);
  t.after(async () => { await first.close(); await second.close(); });
  assert.equal(first.metrics, second.metrics);
  first.metrics.scanned("http");
  second.metrics.scanned("http");
  second.metrics.prevented("http", "redact", { known: 0, pattern: 1, entropy: 0 });
  let text = await (await fetch(`http://127.0.0.1:${port}/metrics`)).text();
  assert.match(text, /vault_guard_scans_total\{surface="http"\} 2/);
  assert.match(text, /vault_guard_secret_matches_prevented_total\{surface="http",action="redact",detector="pattern"\} 1/);
  assert.match(text, /vault_guard_active_instances 2/);

  await first.close();
  await first.close();
  second.metrics.scanned("tool");
  text = await (await fetch(`http://127.0.0.1:${port}/metrics`)).text();
  assert.match(text, /vault_guard_active_instances 1/);
  assert.match(text, /vault_guard_scans_total\{surface="tool"\} 1/);

  const closing = second.close();
  const reopened = await acquireMetrics(port);
  t.after(() => reopened.close());
  await closing;
  text = await (await fetch(`http://127.0.0.1:${port}/metrics`)).text();
  assert.match(text, /vault_guard_active_instances 1/);
  assert.match(text, /vault_guard_scans_total\{surface="http"\} 0/);
});

test("ephemeral listeners stay independent and a failed bind does not poison retries", async (t) => {
  const first = await acquireMetrics(0);
  const second = await acquireMetrics(0);
  t.after(async () => { await first.close(); await second.close(); });
  assert.notEqual(first.port, second.port);
  assert.notEqual(first.metrics, second.metrics);
  first.metrics.scanned("http");
  assert.match(await (await fetch(`http://127.0.0.1:${second.port}/metrics`)).text(), /vault_guard_scans_total\{surface="http"\} 0/);
  await assert.rejects(acquireMetrics(first.port), { code: "EADDRINUSE" });
  await first.close();
  const retry = await acquireMetrics(first.port);
  t.after(() => retry.close());
  assert.match(await (await fetch(`http://127.0.0.1:${retry.port}/metrics`)).text(), /vault_guard_active_instances 1/);
});
