import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { once } from "node:events";
import { parseConfig } from "../src/config.js";
import { Inventory } from "../src/inventory.js";
import { Guard, BLOCKED, BLOCKED_FRAME } from "../src/guard.js";
import { REDACTED } from "../src/scanner.js";
import { serveMetrics, Metrics } from "../src/metrics.js";

const secret = "fixture-credential-without-a-provider-prefix";

function makeGuard(extra: Record<string, unknown> = {}): Guard {
  const config = parseConfig({ env: ["GUARD_TEST_SECRET"], patterns: false, ...extra }, {});
  return new Guard(config, new Inventory(config, { GUARD_TEST_SECRET: secret }));
}

test("an actual local HTTP upstream receives only sanitized JSON, while authentication is preserved", async (t) => {
  const received: { body: string; authorization?: string }[] = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk.toString();
    received.push({ body, authorization: request.headers.authorization });
    response.writeHead(200).end("ok");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const original = JSON.stringify({ messages: [{ role: "user", content: secret }], tools: [{ description: secret }], stream: true });
  const event = { request: new Request(`http://127.0.0.1:${address.port}/v1/chat/completions`, {
    method: "POST", body: original,
    headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(original)), authorization: "Bearer fixture-provider-auth" },
  }) };
  const guard = makeGuard();
  t.after(() => guard.close());
  await guard.http(event);
  assert.equal(event.request.headers.has("content-length"), false);
  assert.equal(await (await fetch(event.request)).text(), "ok");
  assert.equal(received.length, 1);
  assert.equal(received[0]?.body.includes(secret), false);
  assert.equal(received[0]?.authorization, "Bearer fixture-provider-auth");
  assert.equal(JSON.parse(received[0]!.body).stream, true);
  assert.match(guard.metrics.render(), /surface="http",action="redact",detector="known"\} 2/);
});

test("block mode replaces the request with an aborted, credential-free request", async () => {
  const guard = makeGuard({ mode: "block" });
  const event = { request: new Request("https://provider.example.com", { method: "POST", body: JSON.stringify({ input: secret }), headers: { "content-type": "application/json", authorization: "intentional-auth" } }) };
  await guard.http(event);
  assert.equal(event.request.signal.aborted, true);
  assert.equal(event.request.headers.has("authorization"), false);
  assert.equal(await event.request.clone().text(), "{}");
  await assert.rejects(fetch(event.request));
  assert.match(guard.metrics.render(), /reason="secret"/);
  guard.close();
});

test("benign HTTP JSON preserves its exact original bytes", async () => {
  const guard = makeGuard();
  const body = '{ "input": "safe", "max_tokens": 12 }\n';
  const event = { request: new Request("https://provider.example.com", { method: "POST", body, headers: { "content-type": "application/json" } }) };
  await guard.http(event);
  assert.equal(await event.request.text(), body);
  guard.close();
});

test("malformed, oversized, compressed, non-JSON, and multimodal bodies fail closed", async () => {
  const guard = makeGuard({ maxBodyBytes: 1024 });
  const cases: [string, Record<string, string>][] = [
    ["{bad", {}],
    [JSON.stringify({ text: "x".repeat(1025) }), {}],
    ["{}", { "content-encoding": "gzip" }],
    ["{}", { "content-type": "text/plain" }],
    [JSON.stringify({ type: "input_image", image_url: "https://example.com/image.png" }), {}],
    [JSON.stringify({ inlineData: { mimeType: "application/pdf", data: "fixture" } }), {}],
  ];
  for (const [body, headers] of cases) {
    const event = { request: new Request("https://provider.example.com", { method: "POST", body, headers: { "content-type": "application/json", ...headers } }) };
    await guard.http(event);
    assert.equal(event.request.signal.aborted, true);
  }
  guard.close();
});

test("unavailable required inventory never passes a request through", async () => {
  const config = parseConfig({ env: ["MISSING_GUARD_SECRET"] }, {});
  const guard = new Guard(config, new Inventory(config, {}));
  const event = { request: new Request("https://provider.example.com", { method: "POST", body: '{"input":"safe"}', headers: { "content-type": "application/json" } }) };
  await guard.http(event);
  assert.equal(event.request.signal.aborted, true);
  assert.match(guard.metrics.render(), /reason="inventory"/);
  guard.close();
});

test("JSON escaping and stream chunk boundaries cannot hide exact secret values", async () => {
  const guard = makeGuard();
  const escaped = secret.split("").map((char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
  const source = Buffer.from(`{"input":"${escaped}"}`);
  const body = new ReadableStream({ start(controller) {
    controller.enqueue(source.subarray(0, 50));
    controller.enqueue(source.subarray(50));
    controller.close();
  } });
  const event = { request: new Request("https://provider.example.com", { method: "POST", body, duplex: "half", headers: { "content-type": "application/json" } } as RequestInit) };
  await guard.http(event);
  assert.deepEqual(await event.request.json(), { input: REDACTED });
  guard.close();
});

test("WebSocket frames are sanitized and failed inspection overwrites the original frame", async () => {
  const guard = makeGuard();
  const event = { frame: JSON.stringify({ type: "response.create", response: { input: secret } }) };
  await guard.websocket(event);
  assert.equal(JSON.parse(event.frame).response.input, REDACTED);
  event.frame = "malformed " + secret;
  await guard.websocket(event);
  assert.equal(event.frame, BLOCKED_FRAME);
  guard.close();
});

test("tool metadata and structured MCP output are scanned along with display text", async () => {
  const guard = makeGuard();
  const result = await guard.tool({ content: [{ type: "text", text: secret }], output: { nested: [secret] }, metadata: { value: secret } });
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(JSON.stringify(result).split(REDACTED).length - 1, 3);
  assert.deepEqual(await guard.tool({ content: 1n }), { content: BLOCKED });
  guard.close();
});

test("metrics contain only bounded categories and no secret samples", async (t) => {
  const metrics = new Metrics();
  metrics.prevented("http", "redact", { known: 2, pattern: 1, entropy: 0 });
  metrics.blocked("http", "inventory");
  const server = await serveMetrics(metrics, 0);
  t.after(() => { server.closeAllConnections(); server.close(); });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  assert.equal(address.address, "127.0.0.1");
  const response = await fetch(`http://127.0.0.1:${address.port}/metrics`);
  assert.equal(response.status, 200);
  const output = await response.text();
  assert.ok(output.includes('detector="known"} 2'));
  assert.equal(output.includes(secret), false);
  assert.equal((await fetch(`http://127.0.0.1:${address.port}/unknown`)).status, 404);
});
