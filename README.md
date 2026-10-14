# OpenCode Vault Guard

A standalone OpenCode V2 plugin that reduces **accidental credential leakage to LLM providers**. It filters GitHub tokens, AWS credentials, Vault tokens, passwords, private keys, and other recognized secrets from tool results and outgoing model payloads.

The plugin runs locally inside OpenCode. Vault supplies selected known secret values; prompts and tool output are **not sent to Vault for scanning**. There is no separate proxy to deploy and no change to the Vault server.

## Quick start

Requires OpenCode V2. Tested end-to-end with **OpenCode 2.0.25**. Development requires Node 22+ and npm.

```sh
cd ~/repos/opencode-vault-guard
npm ci --ignore-scripts
npm run build
```

Merge this entry into `plugins` in `~/.config/opencode/opencode.jsonc` for all projects, or your project's `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "~/repos/opencode-vault-guard",
      "options": {
        "mode": "redact",
        "metricsPort": 9464
      }
    }
  ]
}
```

Use the **directory**, not `dist/index.js`. OpenCode 2.0.25 requires a root entrypoint for local directory plugins; this package includes `index.js` for that loader. Place the guard after other content-mutating plugins.

Restart the background service after building or registering:

```sh
opencode service restart
```

For an isolated trial, run `opencode --standalone` from a project containing the config. Confirm `vault.guard` is active in that location's plugin list. These files provide registration examples; installing/building this project does not edit your OpenCode configuration.

The minimal setup enables pattern detection without requiring Vault. `examples/opencode.jsonc` is a copyable starting point.

## Add Vault-backed matching

Add a `vault` object to the options:

```jsonc
{
  "mode": "redact",
  "metricsPort": 9464,
  "vault": {
    "address": "https://vault.example.com:8200",
    "tokenFile": "/absolute/path/to/vault-agent-token",
    "secrets": [
      {
        "mount": "kv",
        "path": "development/credentials",
        "fields": ["github_token", "aws_secret_access_key"]
      }
    ]
  }
}
```

This reads `GET /v1/kv/data/development/credentials` and selects the two top-level string fields. Vault ACLs operate on the whole secret path: the Vault response contains the whole KV object, even though only selected fields are retained for matching. Use a narrowly scoped credential collection.

Grant the plugin identity `read` on that path; see `examples/vault-policy.hcl`. No listing, writes, root token, dynamic credential issuance, or Vault Enterprise feature is required. Dynamic credentials already available in environment variables can be included using `env` below.

Authentication choices:

- **Vault Agent token file:** `tokenFile` is an absolute file path, re-read on refresh. Agent handles login and renewal.
- **Environment:** omit `tokenFile` and supply `VAULT_TOKEN` to the **OpenCode server process**, or set `tokenEnv` to another variable name. A token file takes precedence when configured.

`address` defaults to `VAULT_ADDR`; `namespace` defaults to `VAULT_NAMESPACE`. HTTPS is required except for loopback development servers. Normal runtime certificate validation stays enabled. This prototype does not implement Vault CLI-specific TLS variables, login flows, or token renewal.

The inventory loads lazily at the first guarded operation, refreshes after 60 seconds by default, and coalesces concurrent reads. Once refresh is due, a missing field, denied read, timeout, or malformed response blocks payloads until a complete refresh succeeds. Previously observed values remain matched until plugin unload, protecting older conversation content after rotation. Versions never observed by this instance are not in the inventory. Reloading loses that in-memory history.

Values exist in process memory, not a plugin cache file. JavaScript strings cannot be reliably zeroized. The plugin's Vault authentication token is also included in known-value matching.

## Detection and behavior

| Layer | Coverage |
| --- | --- |
| Known values | Selected Vault KV v2 fields and explicitly named environment variables; raw, URI-encoded, JSON-escaped, Base64, and Base64url representations. |
| Patterns | Common GitHub, AWS access-key ID, Vault, GitLab (including runner), Slack, npm, PyPI, SendGrid, OpenAI/Anthropic, Stripe and Google API/OAuth token formats; Twilio key identifiers; Slack/Discord webhook URLs; JWTs, private keys, credential-bearing URLs, authorization text, and credential assignments/JSON fields. |
| Entropy | Optional high-entropy token heuristic, disabled by default to reduce false positives. |

AWS secret access keys and session tokens do not have a universal recognizable prefix. Use exact inventory matching for bare values; the contextual rules also detect labeled assignments such as `AWS_SECRET_ACCESS_KEY=...` and structured credential fields. Pattern findings are suspected credentials, not proof they are live.

Credential URLs include `redis://:password@host` and `rediss://:password@host` without a username. Plain `token=...` assignments are scanned alongside structured token fields. Discord rules cover current, legacy `discordapp.com`, and versioned API URLs. These detectors work without Vault inventory or entropy detection.

`redact` replaces detected spans with `[REDACTED]` and preserves surrounding context. `block` withholds an entire matching payload. Both modes withhold payloads when inspection fails. Redaction scans JSON string values and object keys after JSON decoding, including nested tool metadata and model tool descriptions; benign HTTP JSON retains its original bytes.

The interception points are:

- `tool.execute.after`: successful results, structured output, metadata, and error messages for every tool. Error causes and metadata are dropped.
- `session.http.request`: the native outgoing JSON body, including primary, title, compaction, and session-generation calls using this hook.
- `session.experimental.ws.send`: outgoing JSON WebSocket frames.

HTTP failures install an aborted, empty, credential-free request and raise a generic error. WebSocket failures replace the frame with a fixed non-content error event and raise a generic error. Tool failures produce a fixed withheld-content message. No diagnostic contains a secret prefix or suffix. Failure behavior was exercised inside the real OpenCode host, not only mocked hooks.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `mode` | `"redact"` | `"redact"` or `"block"`. |
| `patterns` | `true` | Enable built-in token and credential-context rules. |
| `entropy` | `false` | Enable entropy heuristic. |
| `env` | `[]` | Names of environment variables whose values must be protected. Every named variable must exist. |
| `maxBodyBytes` | `4194304` | Maximum inspected payload size, 1 KiB–16 MiB. Larger payloads are withheld. |
| `metricsPort` | omitted | Opt-in loopback Prometheus listener. `0` picks an available port, logged at startup. |
| `vault.address` | `VAULT_ADDR` | Vault origin, optionally including a port. No URL credentials, path prefix, query, or fragment. |
| `vault.namespace` | `VAULT_NAMESPACE` | Optional namespace path. |
| `vault.tokenEnv` | `"VAULT_TOKEN"` | Authentication token variable. |
| `vault.tokenFile` | omitted | Absolute token-sink path; overrides `tokenEnv`. |
| `vault.secrets` | required with `vault` | Explicit `{mount, path, fields}` entries for KV v2. |
| `vault.refreshMs` | `60000` | Refresh interval, 1–300 seconds. |
| `vault.timeoutMs` | `3000` | Deadline for the full Vault refresh, 100–10000 ms. |

Example environment inventory: `"env": ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"]`. Only list variables actually set in the OpenCode server's environment. An existing shared service does not inherit environment changes from a newly opened terminal.

Unknown options are rejected. Inventory values must be nonblank strings of 4–65,536 characters; the retained inventory is bounded to 1,000 values and 2 MiB. Nested/non-string KV fields are not supported. Path segments currently accept letters, digits, `_`, and `-`. Exceeding limits withholds payloads rather than evicting protection silently.

## Telemetry: secret exposure prevented

Yes—this is useful telemetry, provided its meaning is precise. The counters measure **matching spans removed or withheld at a guard boundary**, not unique credentials, confirmed compromises, or proof that an entire session is secret-free.

```sh
curl http://127.0.0.1:9464/metrics
```

Metrics:

- `vault_guard_secret_matches_prevented_total{surface,action,detector}`
- `vault_guard_blocked_payloads_total{surface,reason}`
- `vault_guard_scans_total{surface}`
- `vault_guard_active_instances`: plugin instances contributing to the listener.

The only labels are fixed categories:

- `surface`: `tool`, `http`, `websocket`
- `action`: `redact`, `block`
- `detector`: `known`, `pattern`, `entropy`
- `reason`: `inventory`, `format`, `limit`, `secret`, `internal`

Example dashboard query for matches stopped at model dispatch in the last day:

```promql
sum by (detector) (
  increase(vault_guard_secret_matches_prevented_total{surface=~"http|websocket"}[24h])
)
```

Show `surface="tool"` separately for secrets removed before reaching model context. Repeated transcript uploads, retries, and repeated tool reads may count the same credential again. Overlapping detector matches merge into one redacted span; known-value evidence takes precedence. There are no secret values, hashes, names, paths, prompts, provider IDs, user IDs, or session IDs in telemetry.

Metrics are local and opt-in. Nothing is pushed to an external collector. Each OpenCode location has its own plugin instance. Instances using the same fixed metrics port **in one OpenCode process** share a listener and aggregate counters. `vault_guard_active_instances` shows how many are contributing; zero-valued scan counters are exposed before any scans occur. Unloading one instance keeps the listener alive for the others. Counters reset when the final contributing instance unloads or the process exits.

Port `0` creates a separate ephemeral listener per instance. Separate OpenCode processes cannot share a listener; give them different ports. If another process owns a configured port, telemetry binding fails with a generic diagnostic while filtering remains active. This is plugin telemetry, not a metric added to Vault's `/sys/metrics` endpoint.

## Coverage boundaries

This is an accidental-leak guard, not an adversarial sandbox or a complete DLP service.

- A credential must match an inventory value, a pattern, or the enabled entropy heuristic. Splitting values across messages, arbitrary encoding/encryption, and secrets hidden inside opaque binary data can evade detection.
- The prototype is text/JSON focused. Recognized image, audio, document, and file payloads are withheld; it does not perform OCR or unpack arbitrary attachments. Unknown provider-specific binary representations are not certified.
- Compressed/non-JSON HTTP bodies are withheld. For a provider that compresses requests, set `providers.<id>.settings.encoding` to `"none"`. Native signed-body providers are not validated; rewriting a signed request may invalidate its signature.
- Intentional provider authentication headers and request URLs are outside the content filter. Arbitrary HTTP calls made by tools/plugins, MCP transport, web searches, uploads outside session hooks, and direct `ctx.generate.text` calls are not covered by the session-egress guarantee.
- User prompts and pre-existing history can still be stored locally unredacted. The outgoing-request hook changes the provider payload, not the canonical transcript. This cannot retract credentials already sent in an older session.
- The plugin must be loaded and enabled, and later hooks must not reintroduce secrets. Load/import failures, removed plugins, or a malicious agent modifying its own protection require host policy/egress controls beyond this prototype.

## Copilot

**GitHub Copilot as an OpenCode provider** uses the same OpenCode interception boundary. Real-provider Copilot traffic has not been used for validation; the integration test uses a local OpenAI-compatible endpoint.

The standalone **Copilot CLI, VS Code extension, and Copilot SDK** have different extension APIs. This package does not register into those clients. A next adapter can reuse `Scanner`, `Inventory`, and `Guard` behind Copilot's result/prompt hooks or a supported gateway. GitHub's current CLI hook documentation explicitly allows hook failures/timeouts to fall through in several cases, so matching the OpenCode failure behavior needs separate verification. A generic HTTP proxy is another option when the client supports an explicit provider endpoint; a Vault secrets-engine plugin alone is not an LLM egress proxy.

## Verification and development

```sh
npm run typecheck
npm test
npm run build
npm run test:metrics
npm run test:smoke
```

The smoke test requires `vault` and `opencode` on `PATH`. It starts a disposable loopback Vault dev server, creates a scoped reader token, loads the built plugin into an isolated OpenCode process, and sends synthetic credentials through a fake local model endpoint. It validates prompt/tool-output redaction plus block mode, a revoked Vault token, and invalid configuration. No real LLM credentials are used. Enterprise Vault can use an existing `VAULT_LICENSE` or `VAULT_LICENSE_PATH` for the local fixture. Set `VAULT_GUARD_TEST_VAULT` to select another binary or `VAULT_GUARD_TEST_PLUGIN` to test an installed package directory.

`test:metrics` starts one isolated OpenCode server and exercises two project locations against a loopback model endpoint. It checks that both locations contribute scans and redactions to the same fixed-port listener, exposes two active instances, and confirms no synthetic credential reaches the fake provider. It needs only OpenCode on `PATH`; set `OPENCODE_BIN` to select an explicit binary. It uses an isolated service registration and does not restart the user's OpenCode server.

Unit/integration tests cover HTTP delivery, WebSocket frame transformation, JSON escaping, body limits, error handling, rotation, cache refresh, credential context, and telemetry. Native WebSocket delivery has hook-level coverage; a real-provider WebSocket end-to-end test remains future work.

`test/detector-gaps.test.ts` exercises each formerly missing credential family through both the scanner and native HTTP guard in redact/block modes. The shared synthetic corpus is in `test/fixtures/credentials.ts`; boundary cases include truncated tokens, lookalike webhook hosts, trailing token punctuation, and overlapping URI rules.

### Existing-cluster and Copilot trial

`test/live-vault.ts` is an explicitly invoked, installation-specific live integration harness. It uses the existing local Vault cluster and a standalone OpenChamber OpenCode 2.0.25 runtime, then exercises the configured Copilot provider with synthetic canaries. Its trial configuration disables the old guard and enables Vault Guard; original global configuration stays in place.

The harness creates and cleans up a unique KV fixture, an exact-path temporary policy, and a short-lived token. It requires `VAULT_GUARD_LIVE_APPROVED=1`, inherited authentication, and the connection settings described in [the live validation report](docs/live-vault-validation.md). After confirming those settings, invoke it with `npm run test:live`. It is excluded from `npm test`.

The report records observed detection, performance, runtime-state, and cleanup evidence. It also documents a separate credential-exposure incident in a debugging diagnostic outside the guarded trial runtime; passing synthetic tests does not establish that the entire investigation was exposure-free.

`npm pack` produces an installable tarball. The package is marked private to avoid accidental publication while the API is experimental.

## Design references

- [Reference plugin source](https://github.com/jscheel/opencode-secrets-protect/blob/master/src/index.ts): V1 `tool.execute.after` filter for `read`, `bash`, and `grep`, blocking the full output. This implementation is new code with broader V2 interception and Vault inventory matching.
- [OpenCode V2 plugin hooks](https://opencode.ai/v2/docs/build/plugins) and [registration](https://opencode.ai/v2/docs/plugins).
- [OpenCode providers, compression, and WebSocket behavior](https://opencode.ai/v2/docs/providers).
- [Vault KV v2 read API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version).
- [Copilot hook contracts and failure behavior](https://docs.github.com/en/copilot/reference/hooks-reference).
