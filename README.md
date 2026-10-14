# OpenCode Vault Guard

OpenCode Vault Guard is a local OpenCode V2 plugin that reduces accidental credential leakage to LLM providers. It scans tool results and outgoing model payloads for known secret values and common credential formats, then redacts or blocks matching content.

Vault is an optional source of known secret values. Prompts and tool output are scanned locally and are **not sent to Vault**. The plugin does not require a proxy or changes to the Vault server.

> **Status:** Experimental. End-to-end tested with OpenCode 2.0.25. Requires Node.js 22 or newer. The package declares an OpenCode peer dependency of `>=2.0.25 <2.1.0`.

## Contents

- [Quick start](#quick-start)
- [Add Vault-backed matching](#add-vault-backed-matching)
- [Configuration reference](#configuration-reference)
- [How inspection works](#how-inspection-works)
- [Metrics](#metrics)
- [Limitations and security boundaries](#limitations-and-security-boundaries)
- [Development and tests](#development-and-tests)
- [Copilot compatibility](#copilot-compatibility)
- [References](#references)

## Quick start

Install dependencies and build the plugin:

```sh
cd ~/repos/opencode-vault-guard
npm ci --ignore-scripts
npm run build
```

`dist/` is Git-ignored, so a fresh clone must run the build before OpenCode can load `index.js`. The commands above use `--ignore-scripts`, which skips lifecycle hooks. For a Git URL npm dependency, `prepare` builds `dist/` during installation; a prebuilt npm tarball also includes `dist/` through `prepack`. Keep Node.js 22+ and the build dependencies available when installing from Git.

Register the **package directory** in `~/.config/opencode/opencode.jsonc` (all projects) or a project's `opencode.jsonc`:

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

Merge this entry into the existing `plugins` array if needed. Use the directory, not `dist/index.js`: OpenCode 2.0.25 expects a root entrypoint for local directory plugins, and this package's `index.js` loads the built plugin. Place Vault Guard after other plugins that modify content.

Restart the background service after building or changing registration:

```sh
opencode service restart
```

For an isolated trial, run `opencode --standalone` from a project with the config and confirm `vault.guard` is active in that location's plugin list. The examples in [`examples/`](examples/) are starting points; building or installing this package does not edit OpenCode configuration.

This minimal configuration enables built-in pattern detection and does not require Vault. See [`examples/opencode.jsonc`](examples/opencode.jsonc) for a copyable version.

## Add Vault-backed matching

Vault matching adds exact-value detection for explicitly selected KV v2 fields and configured environment variables. Add a `vault` object to the plugin options:

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

This reads `GET /v1/kv/data/development/credentials` and retains the selected top-level string fields for matching. Vault ACLs apply to the whole secret path: the response includes the full KV object, even though the plugin only retains the named fields. Prefer a narrowly scoped credential collection. Grant the plugin identity `read` on the path; see [`examples/vault-policy.hcl`](examples/vault-policy.hcl). The plugin does not list secrets, write to Vault, issue dynamic credentials, or require a Vault Enterprise feature.

Authentication options:

- **Vault Agent token file:** Set `tokenFile` to an absolute path. The file is re-read on refresh; Vault Agent handles login and renewal.
- **Environment variable:** Omit `tokenFile` and provide `VAULT_TOKEN` to the OpenCode server process, or set `tokenEnv` to another variable name. A configured token file takes precedence.

`address` defaults to `VAULT_ADDR`; `namespace` defaults to `VAULT_NAMESPACE`. HTTPS is required except for loopback development servers. Standard TLS certificate validation remains enabled. Vault CLI-specific TLS variables, login flows, and token renewal are not implemented by this plugin.

The inventory loads on the first guarded operation and refreshes every 60 seconds by default. Concurrent reads are coalesced. If a refresh is due and any configured field is missing, access is denied, the request times out, or the response is malformed, payloads are withheld until a complete refresh succeeds. Values seen previously remain matched until the plugin unloads, so rotation does not expose older conversation content. Versions this instance has never observed are not in its inventory; reloading clears the in-memory history.

Secret values and the Vault authentication token are held in process memory, not in a plugin cache file. JavaScript strings cannot be reliably zeroized.

## Configuration reference

Unknown options are rejected. Defaults and valid ranges are enforced during plugin setup.

| Option | Default | Description |
| --- | --- | --- |
| `mode` | `"redact"` | `"redact"` replaces matches; `"block"` withholds the whole matching payload. |
| `patterns` | `true` | Enable built-in token and credential-context rules. |
| `entropy` | `false` | Enable the high-entropy token heuristic. Disabled by default to reduce false positives. |
| `env` | `[]` | Names of environment variables whose values should be matched. Every listed variable must exist. Example: `["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"]`. |
| `maxBodyBytes` | `4194304` | Maximum inspected payload size (1 KiB–16 MiB). Larger payloads are withheld. |
| `metricsPort` | omitted | Opt-in loopback Prometheus listener. Set to `0` to select an available port; the chosen port is logged at startup. |
| `vault.address` | `VAULT_ADDR` | Vault origin, optionally with a port. URL credentials, path prefixes, queries, and fragments are not accepted. |
| `vault.namespace` | `VAULT_NAMESPACE` | Optional namespace path. |
| `vault.tokenEnv` | `"VAULT_TOKEN"` | Environment variable containing the Vault token. |
| `vault.tokenFile` | omitted | Absolute path to a Vault Agent token file. Overrides `tokenEnv`. |
| `vault.secrets` | required when `vault` is set | Explicit KV v2 `{mount, path, fields}` entries. |
| `vault.refreshMs` | `60000` | Inventory refresh interval (1–300 seconds). |
| `vault.timeoutMs` | `3000` | Deadline for the full Vault refresh (100–10000 ms). |

Additional limits: inventory values must be nonblank strings of 4–65,536 characters; the retained inventory is capped at 1,000 values and 2 MiB. Nested or non-string KV fields are unsupported. Mount and path segments currently accept letters, digits, `_`, and `-`. Exceeding an inventory limit withholds payloads rather than silently dropping protection.

Environment variables are read by the OpenCode server process. An already-running shared service does not inherit environment changes from a newly opened terminal; restart it after changing its environment.

## How inspection works

### Detection

| Detector | What it checks |
| --- | --- |
| Known values | Selected Vault KV v2 fields, the Vault authentication token, and explicitly named environment variables. Also matches raw, URI-encoded, JSON-escaped, Base64, and Base64url representations. |
| Patterns | Common GitHub, AWS access-key ID, Vault, GitLab (including runner), Slack, npm, PyPI, SendGrid, OpenAI/Anthropic, Stripe, and Google API/OAuth token formats; Twilio key identifiers; Slack/Discord webhook URLs; JWTs; private keys; credential-bearing URLs (including Redis); authorization text; and credential assignments/JSON fields. |
| Entropy | Optional high-entropy token heuristic. Disabled by default. |

AWS secret access keys and session tokens have no universal recognizable prefix. Use exact inventory matching for bare values; contextual rules can also detect labeled values such as `AWS_SECRET_ACCESS_KEY=...` and structured credential fields. Pattern matches are suspected credentials, not proof that a credential is live.

Rules for plain `token=...` assignments and structured token fields work without Vault or entropy detection. Discord webhook detection includes current and legacy hosts and versioned API URLs.

### Interception and failure behavior

| OpenCode hook | Inspected content |
| --- | --- |
| `tool.execute.after` | Successful results and tool error messages for every tool, including structured output and metadata. Error causes and metadata are dropped. |
| `session.http.request` | Native outgoing JSON bodies, including primary, title, compaction, and session-generation requests that use this hook. |
| `session.experimental.ws.send` | Outgoing JSON WebSocket frames. |

In `redact` mode, detected spans become `[REDACTED]` and surrounding context is preserved. In `block` mode, the entire matching payload is withheld. Inspection failures are withheld in either mode. JSON string values and object keys are scanned after decoding, including nested tool metadata and model tool descriptions. HTTP JSON with no match retains its original bytes.

Failures use fixed, credential-free messages: HTTP requests are replaced with an aborted empty request, WebSocket frames with a non-content error event, and tool output with a withheld-content message. Diagnostics do not include secret prefixes or suffixes. Failure behavior has also been exercised inside the OpenCode host, not only with mocked hooks.

## Metrics

Metrics are opt-in, local to the machine, and served on loopback. Nothing is pushed to an external collector. With `metricsPort: 9464`, inspect them with:

```sh
curl http://127.0.0.1:9464/metrics
```

Available counters and gauge:

- `vault_guard_secret_matches_prevented_total{surface,action,detector}` — matching spans removed or withheld at a guard boundary.
- `vault_guard_blocked_payloads_total{surface,reason}` — payloads withheld, including inspection failures.
- `vault_guard_scans_total{surface}` — payloads inspected.
- `vault_guard_active_instances` — plugin instances contributing to the listener.

Labels are fixed categories only: `surface` is `tool`, `http`, or `websocket`; `action` is `redact` or `block`; `detector` is `known`, `pattern`, or `entropy`; `reason` is `inventory`, `format`, `limit`, `secret`, or `internal`. Metrics contain no secret values or hashes, secret names or paths, prompts, provider IDs, user IDs, or session IDs.

The match counter is **not** a count of unique credentials, confirmed compromises, or proof that an entire session is secret-free. Repeated transcript uploads, retries, and tool reads can count the same credential again. Overlapping matches are merged into one redacted span, with known-value evidence taking precedence. Use `surface="tool"` to track removals before model context; `surface=~"http|websocket"` tracks matches at model dispatch. For example, matches stopped at model dispatch over the previous day, grouped by detector:

```promql
sum by (detector) (
  increase(vault_guard_secret_matches_prevented_total{surface=~"http|websocket"}[24h])
)
```

Instances in one OpenCode process that use the same fixed port share a listener and aggregate counters. Unloading one instance leaves it available to the others; counters reset when the last instance unloads or the process exits. Port `0` creates a separate ephemeral listener per instance. Separate OpenCode processes cannot share a listener, so use different ports. If a configured port is already owned by another process, metrics binding fails with a generic diagnostic while filtering remains active. These are plugin metrics, not metrics added to Vault's `/sys/metrics` endpoint.

## Limitations and security boundaries

Vault Guard is an accidental-leak guard, not an adversarial sandbox or a complete DLP service.

- Detection depends on a known inventory value, a built-in pattern, or the optional entropy heuristic. Split values, arbitrary encoding/encryption, and secrets inside opaque binary data can evade detection.
- Inspection is text/JSON focused. Recognized image, audio, document, and file payloads are withheld; OCR and arbitrary attachment unpacking are not supported. Unknown provider-specific binary formats are not certified.
- Compressed or non-JSON HTTP bodies are withheld. For a provider that compresses requests, set `providers.<id>.settings.encoding` to `"none"`. Native signed-body providers are not validated; rewriting a signed request may invalidate its signature.
- Intentional provider authentication headers and request URLs are outside the content filter. Arbitrary HTTP calls made by tools or plugins, MCP transport, web searches, uploads outside session hooks, and direct `ctx.generate.text` calls are not covered by the session-egress guarantee.
- Prompts and existing history can remain stored locally without redaction. The outgoing-request hook changes the provider payload, not the canonical transcript, and cannot retract credentials sent in an earlier session.
- Protection requires the plugin to load and remain enabled. Later hooks could reintroduce secrets. Host policy or egress controls are needed for guarantees against plugin load/import failures, plugin removal, or a malicious agent modifying its own protection.

## Development and tests

### Local workflow

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
```

| Command | Purpose and requirements |
| --- | --- |
| `npm run typecheck` | Type-check source and tests without emitting files. |
| `npm test` | Run the unit and integration test suite. |
| `npm run build` | Compile the plugin into `dist/`. |
| `npm run test:smoke` | Run an isolated host-level smoke test. Requires `vault` and `opencode` on `PATH`; uses a disposable loopback Vault dev server and a fake local model endpoint, not real LLM credentials. |
| `npm run test:metrics` | Verify metrics and redaction from two OpenCode locations against a loopback fake model. Requires OpenCode on `PATH`; set `OPENCODE_BIN` to choose a binary. Does not restart the user's OpenCode service. |
| `npm run test:live` | Explicit, installation-specific live Vault/Copilot harness; see [Live Vault validation](#live-vault-validation). Not part of `npm test`. |

For the smoke test, `VAULT_GUARD_TEST_VAULT` selects the Vault binary and `VAULT_GUARD_TEST_PLUGIN` selects a built plugin directory. Enterprise Vault can use an existing `VAULT_LICENSE` or `VAULT_LICENSE_PATH` for the local fixture.

The unit and integration tests cover HTTP delivery, WebSocket frame transformation, JSON escaping, body limits, error handling, secret rotation and refresh, credential context, and metrics. Native WebSocket delivery has hook-level coverage; a real-provider WebSocket end-to-end test remains future work. `test/detector-gaps.test.ts` exercises the credential families in both scanner and HTTP-guard paths; the shared synthetic corpus is in `test/fixtures/credentials.ts`.

### Project layout

| Path | Responsibility |
| --- | --- |
| `index.js` | Root entrypoint used by OpenCode's local directory plugin loader. |
| `src/index.ts` | Registers OpenCode hooks and owns plugin setup/teardown. |
| `src/config.ts` | Validates plugin options and applies defaults. |
| `src/inventory.ts` | Loads configured environment/Vault values and refreshes the in-memory inventory. |
| `src/scanner.ts` | Detects and redacts known values, patterns, and optional entropy matches. |
| `src/guard.ts` | Applies inspection and failure behavior at tool, HTTP, and WebSocket boundaries. |
| `src/metrics.ts` | Maintains counters and serves the optional Prometheus endpoint. |
| `test/` | Unit, integration, host smoke, and live-test harnesses. |
| `examples/` | OpenCode configuration examples and a sample Vault policy. |

### Live Vault validation

`test/live-vault.ts` targets an existing loopback Vault cluster and a standalone OpenCode 2.0.25+ runtime, then exercises an explicitly selected Copilot model with synthetic canaries. The trial configuration disables the replaced plugin and enables Vault Guard; the original global configuration remains in place.

The harness creates and cleans up a unique KV fixture, an exact-path temporary policy, and a short-lived token. It requires `VAULT_GUARD_LIVE_APPROVED=1`, inherited `VAULT_TOKEN`, `VAULT_GUARD_LIVE_NAMESPACE`, and `VAULT_GUARD_LIVE_MODEL=github-copilot/<model-id>`. Set `VAULT_ADDR` (defaults to `http://127.0.0.1:8200`) and `VAULT_GUARD_LIVE_MOUNT` (defaults to `kv`) for the selected KV v2 mount. It reads `~/.config/opencode/opencode.json` by default; set `VAULT_GUARD_LIVE_CONFIG_FILE` to a different JSON config file and `VAULT_GUARD_LIVE_OPENCODE` to choose a binary instead of `opencode` on `PATH`. `VAULT_GUARD_LIVE_TMPDIR` overrides the platform temporary directory.

Optional: `VAULT_GUARD_LIVE_REPLACED_PLUGIN` names the plugin to disable (default `opencode-secrets-protect`); `VAULT_GUARD_LIVE_REQUIRED_PLUGINS` is a comma-separated list of other plugin IDs whose active state must be verified. `VAULT_GUARD_LIVE_SNAPSHOT_FILES` is a platform-path-delimiter-separated list of additional files to check for unchanged content/mode. `VAULT_GUARD_LIVE_SERVER` enables a before/after PID and version check of an existing shared service; without it the harness does not contact a shared service. Review the target and permissions before explicitly running `npm run test:live`. This test is excluded from `npm test`.

Local trial artifacts are written under ignored `docs/` only after an approved run starts, and are not part of Git or the npm package. Do not publish these installation-specific results without reviewing them for sensitive metadata. A previously conducted limited Copilot trial observed detection, performance, and cleanup, but synthetic canaries do not establish that an entire investigation was exposure-free.

`npm pack` produces an installable tarball. The package is marked private to avoid accidental publication while its API is experimental.

## Copilot compatibility

GitHub Copilot used **as an OpenCode provider** goes through the same OpenCode interception boundary. A limited live trial with synthetic canaries exercised Copilot over native HTTP as well as the local OpenAI-compatible test endpoint. It did not establish comprehensive coverage of Copilot traffic or validate real-provider WebSocket delivery.

The standalone Copilot CLI, VS Code extension, and Copilot SDK have different extension APIs. This package does not register with those clients. An adapter could reuse `Scanner`, `Inventory`, and `Guard` behind their supported prompt/result hooks or a supported gateway. GitHub's current CLI hook documentation allows some failures and timeouts to fall through, so matching OpenCode's failure behavior requires separate validation. A generic HTTP proxy is another option when a client supports an explicit provider endpoint; a Vault secrets-engine plugin alone is not an LLM egress proxy.

## References

- [OpenCode V2 plugin hooks](https://opencode.ai/v2/docs/build/plugins) and [plugin registration](https://opencode.ai/v2/docs/plugins).
- [OpenCode providers, compression, and WebSocket behavior](https://opencode.ai/v2/docs/providers).
- [Vault KV v2 read API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version).
- [Copilot hook contracts and failure behavior](https://docs.github.com/en/copilot/reference/hooks-reference).
- [Reference plugin source](https://github.com/jscheel/opencode-secrets-protect/blob/master/src/index.ts): a V1 `tool.execute.after` filter for selected tools that blocks full output. Vault Guard is new code with broader V2 interception and Vault inventory matching.
