import assert from "node:assert/strict";
import { test } from "node:test";
import { parseConfig } from "../src/config.js";
import { Guard } from "../src/guard.js";
import { Scanner, REDACTED, matchCount } from "../src/scanner.js";
import { credentialFixtures } from "./fixtures/credentials.js";

for (const fixture of credentialFixtures) {
  test(`${fixture.name}: patterns redact every occurrence without Vault or entropy`, () => {
    const scanner = new Scanner([], { patterns: true, entropy: false });
    const result = scanner.scan(`before\n${fixture.value}\nbetween\n${fixture.value}\nafter`);
    assert.equal(result.value, `before\n${REDACTED}\nbetween\n${REDACTED}\nafter`);
    assert.deepEqual(result.counts, { known: 0, pattern: 2, entropy: 0 });
    assert.equal(matchCount(scanner.scan(result.value).counts), 0);
  });

  test(`${fixture.name}: native HTTP payload is sanitized and block mode withholds it`, async () => {
    for (const mode of ["redact", "block"] as const) {
      const guard = new Guard(parseConfig({ mode }, {}));
      const event = { request: new Request("https://provider.example.com/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ messages: [{ role: "user", content: fixture.value }] }),
      }) };
      try {
        await guard.http(event);
        assert.equal(event.request.signal.aborted, mode === "block");
        const body = await event.request.text();
        assert.equal(body.includes(fixture.value), false);
        if (mode === "redact") assert.equal(JSON.parse(body).messages[0].content, REDACTED);
        assert.ok(guard.metrics.render().includes(`action="${mode}",detector="pattern"} 1`));
      } finally {
        guard.close();
      }
    }
  });
}

test("webhook host boundaries and truncated credentials avoid the new pattern rules", () => {
  const scanner = new Scanner([], { patterns: true, entropy: false });
  const examples = [
    "SG." + "a".repeat(21) + "." + "b".repeat(43),
    "SK" + "a".repeat(31),
    "SK" + "a".repeat(33),
    "pypi-" + "a".repeat(49),
    "glrt-" + "a".repeat(19),
    "ya29.",
    "https://hooks.slack.com.example.org/services/TAAAAAAAA/BBBBBBBBB/" + "c".repeat(24),
    "https://discord.com.example.org/api/webhooks/123456789/" + "d".repeat(68),
    "redis://localhost:6379/0",
    "tokenizer=ordinary-identifier",
    "tokens=ordinary-identifier",
  ];
  for (const example of examples) {
    assert.equal(matchCount(scanner.scan(example).counts), 0, "benign or malformed lookalike was detected");
  }
});

test("legacy and versioned Discord webhooks and TLS Redis URLs are protected", () => {
  const scanner = new Scanner([], { patterns: true, entropy: false });
  for (const value of [
    "https://discordapp.com/api/webhooks/123456789/" + "d".repeat(68),
    "https://discord.com/api/v10/webhooks/123456789/" + "d".repeat(68) + "?wait=true",
    "https://hooks.slack.com/services/TAAAAAAAA/BBBBBBBBB/" + "c".repeat(24) + "?source=fixture",
    "rediss://:synthetic-redis-canary@localhost:6380/0",
    "redis://user:synthetic-redis-canary@localhost:6379/0",
  ]) {
    const result = scanner.scan(value);
    assert.equal(result.value, REDACTED);
    assert.equal(result.counts.pattern, 1, "overlapping URI rules must count the same match once");
  }
});

test("token assignments support quoted values, case, and JSON field context", () => {
  const scanner = new Scanner([], { patterns: true, entropy: false });
  for (const value of [
    'token="synthetic-token-value"',
    "TOKEN = 'synthetic-token-value'",
    '{"token":"synthetic-token-value"}',
    { token: "synthetic-token-value", unrelated: "keep this text" },
  ]) {
    const result = scanner.scan(value);
    assert.equal(JSON.stringify(result.value).includes("synthetic-token-value"), false);
    assert.equal(result.counts.pattern, 1);
  }
});

test("a credential label followed by long whitespace without an assignment remains unchanged", () => {
  const scanner = new Scanner([], { patterns: true, entropy: false });
  const text = "token" + " ".repeat(64 * 1024) + "ordinary documentation";
  const result = scanner.scan(text);
  assert.equal(result.value, text);
  assert.equal(matchCount(result.counts), 0);
});
