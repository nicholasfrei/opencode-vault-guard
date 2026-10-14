import assert from "node:assert/strict";
import { test } from "node:test";
import { Scanner, REDACTED, matchCount } from "../src/scanner.js";

test("known secrets are removed from nested fields, keys, and common encodings", () => {
  const secret = 'fixture/credential+with"quotes\nand spaces';
  const encoded = [secret, encodeURIComponent(secret), Buffer.from(secret).toString("base64"), Buffer.from(secret).toString("base64url"), JSON.stringify(secret).slice(1, -1)];
  const scanner = new Scanner([secret], { patterns: false, entropy: false });
  const result = scanner.scan({ messages: encoded.map((text) => ({ text })), [secret]: "safe" });
  assert.equal(result.counts.known, encoded.length + 1);
  const output = JSON.stringify(result.value);
  for (const value of encoded) assert.equal(output.includes(JSON.stringify(value).slice(1, -1)), false);
  assert.ok(output.includes(REDACTED));
});

test("overlapping exact and pattern matches count once and never reveal prefixes", () => {
  const secret = "ghp_" + "aB3".repeat(12);
  const result = new Scanner([secret, secret.slice(5)], { patterns: true, entropy: false }).scan(`before ${secret} after ${secret}`);
  assert.equal(result.value, `before ${REDACTED} after ${REDACTED}`);
  assert.deepEqual(result.counts, { known: 2, pattern: 0, entropy: 0 });
});

test("standalone pattern rules scan all matches and remove entire private keys", () => {
  const token = "hvs." + "z9".repeat(16);
  const key = ["-----BEGIN PRIVATE KEY-----", "synthetic-test-data", "-----END PRIVATE KEY-----"].join("\n");
  const result = new Scanner([], { patterns: true, entropy: false }).scan(`${token}\n${key}\n${token}`);
  assert.equal(result.value, [REDACTED, REDACTED, REDACTED].join("\n"));
  assert.equal(result.counts.pattern, 3);
});

test("an incomplete private key blocks the remainder instead of leaving key material", () => {
  const result = new Scanner([], { patterns: true, entropy: false }).scan("-----BEGIN RSA PRIVATE KEY-----\npartial-material");
  assert.equal(result.value, REDACTED);
});

test("ordinary source identifiers, paths, hashes, and safe text survive default scanning", () => {
  const text = "SessionHttpRequest /src/config.ts https://example.com 9f" + "a3".repeat(31);
  const result = new Scanner([], { patterns: true, entropy: false }).scan(text);
  assert.equal(result.value, text);
  assert.equal(matchCount(result.counts), 0);
});

test("entropy detection is opt-in", () => {
  const text = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV";
  assert.equal(new Scanner([], { patterns: false, entropy: false }).scan(text).value, text);
  assert.equal(new Scanner([], { patterns: false, entropy: true }).scan(text).value, REDACTED);
});

test("AWS secret keys and session tokens are detected by assignment or structured key context", () => {
  const scanner = new Scanner([], { patterns: true, entropy: false });
  const value = "syntheticAwsCredentialValueWithoutAnyKnownPrefix";
  for (const key of ["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "password", "api_key", "access_token"]) {
    const result = scanner.scan({ [key]: value });
    assert.equal((result.value as Record<string, unknown>)[key], REDACTED);
    assert.equal(result.counts.pattern, 1);
    assert.equal(JSON.stringify(scanner.scan(`${key}=${value}`).value).includes(value), false);
    assert.equal(matchCount(scanner.scan(result.value).counts), 0, "already-redacted fields must not inflate counters");
  }
});

test("object traversal preserves prototype-looking keys without prototype pollution", () => {
  const input = JSON.parse('{"__proto__":{"marker":"safe"},"constructor":"safe"}');
  const result = new Scanner([], { patterns: false, entropy: false }).scan(input);
  assert.equal(JSON.stringify(result.value), JSON.stringify(input));
  assert.equal(Object.getPrototypeOf(result.value), null);
});

test("key collisions and excessively deep payloads are rejected rather than partially scanned", () => {
  const scanner = new Scanner(["fixture-one", "fixture-two"], { patterns: false, entropy: false });
  assert.throws(() => scanner.scan({ "fixture-one": 1, "fixture-two": 2 }), /format/);
  let nested: unknown = "safe";
  for (let i = 0; i < 70; i++) nested = [nested];
  assert.throws(() => scanner.scan(nested), /limit/);
});
