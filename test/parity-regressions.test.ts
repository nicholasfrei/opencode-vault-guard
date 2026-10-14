import assert from "node:assert/strict";
import { test } from "node:test";
import { parseConfig } from "../src/config.js";
import { Guard } from "../src/guard.js";
import { Scanner, REDACTED, matchCount } from "../src/scanner.js";

const scanner = (entropy = false) => new Scanner([], { patterns: true, entropy });

async function outgoing(text: string, options: { entropy?: boolean; mode?: "redact" | "block" } = {}) {
  const guard = new Guard(parseConfig({ entropy: options.entropy ?? false, mode: options.mode ?? "redact" }, {}));
  const event = { request: new Request("https://provider.example/v1/chat", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: text }),
  }) };
  try {
    await guard.http(event);
    return { body: await event.request.text(), aborted: event.request.signal.aborted };
  } finally {
    guard.close();
  }
}

test("quoted assignments remove the entire value, including spaces and escaped quotes", async () => {
  const assignments = [
    'password="abcdefghijkl synthetic-suffix"',
    'pwd="abcdefghijkl synthetic-suffix \\" quoted"',
    "secret='abcdefghijkl synthetic-suffix'",
    'password="abcdefghijkl synthetic-suffix', // unterminated: do not expose the trailing words
    'password="abcdefghijkl\nsynthetic-suffix"',
  ];
  for (const value of assignments) {
    const result = scanner().scan(`before ${value} after`);
    assert.equal(String(result.value).includes("synthetic-suffix"), false);
    assert.equal(result.counts.pattern, 1);
    const sent = await outgoing(value);
    assert.equal(sent.aborted, false);
    assert.equal(sent.body.includes("synthetic-suffix"), false);
    const blocked = await outgoing(value, { mode: "block" });
    assert.equal(blocked.aborted, true);
    assert.equal(blocked.body.includes("synthetic-suffix"), false);
  }
});

test("entropy matches redact a complete long lexical run, not only its first 256 characters", async () => {
  const token = "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz_+/=".repeat(8) + "suffix000000000000000000000000000000";
  assert.ok(token.length > 256);
  const result = scanner(true).scan(`before ${token} after`);
  assert.equal(result.value, `before ${REDACTED} after`);
  assert.equal(result.counts.entropy, 1);
  const sent = await outgoing(token, { entropy: true });
  assert.equal(sent.aborted, false);
  assert.equal(JSON.parse(sent.body).message, REDACTED);
  assert.equal((await outgoing(token, { entropy: true, mode: "block" })).aborted, true);
});

test("additional token and assignment formats are protected without enabling entropy", async () => {
  const fixtures = [
    "xoxb-abcde12345", // shorter Slack token
    "A".repeat(24) + ".bC1234." + "d".repeat(27), // Discord bot token
    "heroku=01234567-89ab-cdef-0123-456789abcdef",
    "secret=abcdefghijklmnop",
    "pwd=abcdefghijklmnop",
  ];
  for (const value of fixtures) {
    assert.equal(scanner().scan(value).value, REDACTED);
    assert.equal(JSON.parse((await outgoing(value)).body).message, REDACTED);
  }
  assert.equal(JSON.stringify(scanner().scan({ secret: "abcdefghijklmnop", pwd: "abcdefghijklmnop" }).value),
    JSON.stringify({ secret: REDACTED, pwd: REDACTED }));
});

test("source references survive contextual heuristics, but known values still take precedence", async () => {
  const references = [
    "const token = process.env.VAULT_TOKEN",
    'password = process.env["PASSWORD"]',
    "const secret = import.meta.env.API_KEY",
  ];
  for (const value of references) {
    assert.equal(scanner().scan(value).value, value);
    assert.equal(matchCount(scanner().scan(value).counts), 0);
    assert.equal(JSON.parse((await outgoing(value)).body).message, value);
  }
  assert.equal(JSON.stringify(scanner().scan({ password: "process.env.VAULT_TOKEN" }).value),
    JSON.stringify({ password: "process.env.VAULT_TOKEN" }));
  const known = new Scanner(["process.env.VAULT_TOKEN"], { patterns: true, entropy: false });
  assert.equal(known.scan("token=process.env.VAULT_TOKEN").value, `token=${REDACTED}`);
});
