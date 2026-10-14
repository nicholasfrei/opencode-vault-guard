import { createServer } from "node:http";
import type { Server } from "node:http";
import type { BlockReason } from "./errors.js";
import type { Counts } from "./scanner.js";

export type Surface = "http" | "websocket" | "tool";

export class Metrics {
  #counters = new Map<string, number>();

  constructor() {
    for (const surface of ["http", "websocket", "tool"] as const) {
      this.increment("vault_guard_scans_total", { surface }, 0);
    }
  }

  private increment(name: string, labels: Record<string, string>, amount = 1): void {
    const key = `${name}{${Object.entries(labels).map(([name, value]) => `${name}="${value}"`).join(",")}}`;
    this.#counters.set(key, (this.#counters.get(key) ?? 0) + amount);
  }

  scanned(surface: Surface): void {
    this.increment("vault_guard_scans_total", { surface });
  }

  prevented(surface: Surface, action: "redact" | "block", counts: Counts): void {
    for (const detector of ["known", "pattern", "entropy"] as const) {
      if (counts[detector]) this.increment("vault_guard_secret_matches_prevented_total", { surface, action, detector }, counts[detector]);
    }
  }

  blocked(surface: Surface, reason: BlockReason): void {
    this.increment("vault_guard_blocked_payloads_total", { surface, reason });
  }

  render(): string {
    return [
      "# HELP vault_guard_scans_total Payloads inspected at a guard boundary.",
      "# TYPE vault_guard_scans_total counter",
      "# HELP vault_guard_secret_matches_prevented_total Matching spans removed or withheld; not unique secrets or confirmed incidents.",
      "# TYPE vault_guard_secret_matches_prevented_total counter",
      "# HELP vault_guard_blocked_payloads_total Payloads withheld by reason, including inspection failures.",
      "# TYPE vault_guard_blocked_payloads_total counter",
      ...[...this.#counters.entries()].map(([key, count]) => `${key} ${count}`),
      "",
    ].join("\n");
  }
}

export async function serveMetrics(metrics: Metrics, port: number, activeInstances?: () => number): Promise<Server> {
  const server = createServer((request, response) => {
    if (request.method !== "GET" || request.url !== "/metrics") {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8", "Cache-Control": "no-store" });
    const instances = activeInstances
      ? `# HELP vault_guard_active_instances Plugin instances contributing to this listener.\n# TYPE vault_guard_active_instances gauge\nvault_guard_active_instances ${activeInstances()}\n`
      : "";
    response.end(metrics.render() + instances);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  server.unref();
  return server;
}

interface SharedListener {
  metrics: Metrics;
  server: Promise<Server>;
  users: number;
  closing?: Promise<void>;
}

export interface MetricsLease {
  metrics: Metrics;
  port: number;
  close(): Promise<void>;
}

const registryKey = Symbol.for("vault.guard.metrics.listeners.v1");
const runtime = globalThis as typeof globalThis & { [registryKey]?: Map<number, SharedListener> };

// OpenCode creates location-scoped plugin instances, including across module reloads.
// Fixed ports share one process-local registry; port 0 deliberately remains instance-local.
export async function acquireMetrics(port: number): Promise<MetricsLease> {
  const registry = runtime[registryKey] ??= new Map();
  let entry = port === 0 ? undefined : registry.get(port);
  if (entry?.closing) {
    await entry.closing;
    return acquireMetrics(port);
  }
  if (!entry) {
    const metrics = new Metrics();
    const created: SharedListener = { metrics, server: serveMetrics(metrics, port, () => created.users), users: 0 };
    entry = created;
    if (port !== 0) registry.set(port, entry);
  }
  const shared = entry;
  shared.users++;
  let server: Server;
  try {
    server = await shared.server;
  } catch (error) {
    shared.users--;
    if (registry.get(port) === shared) registry.delete(port);
    throw error;
  }
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Vault Guard: metrics listener address unavailable.");
  let closed = false;
  return {
    metrics: shared.metrics,
    port: address.port,
    async close() {
      if (closed) return;
      closed = true;
      if (--shared.users !== 0) return;
      shared.closing = new Promise<void>((resolve) => {
        server.close(() => {
          if (registry.get(port) === shared) registry.delete(port);
          resolve();
        });
        server.closeAllConnections();
      });
      await shared.closing;
    },
  };
}
