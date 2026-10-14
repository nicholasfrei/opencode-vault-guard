import { open } from "node:fs/promises";
import type { Config } from "./config.js";
import { GuardError } from "./errors.js";
import { readText } from "./io.js";

export class Inventory {
  #values = new Set<string>();
  #expires = 0;
  #loading?: Promise<readonly string[]>;
  #closed = false;
  #controller = new AbortController();

  constructor(
    private readonly config: Config,
    private readonly env: NodeJS.ProcessEnv = process.env,
    private readonly request: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
  ) {}

  async values(): Promise<readonly string[]> {
    if (this.#closed) throw new GuardError("inventory");
    if (this.now() < this.#expires) return [...this.#values];
    this.#loading ??= this.refresh().finally(() => { this.#loading = undefined; });
    return this.#loading;
  }

  private async refresh(): Promise<readonly string[]> {
    try {
      const next = new Set(this.#values);
      const add = (value: unknown) => {
        if (typeof value !== "string" || value.length < 4 || value.length > 65_536 || !value.trim()) {
          throw new GuardError("inventory");
        }
        next.add(value);
      };
      for (const name of this.config.env) add(this.env[name]);
      const vault = this.config.vault;
      if (vault) {
        let token = this.env[vault.tokenEnv];
        if (vault.tokenFile) {
          const file = await open(vault.tokenFile, "r");
          try {
            const stat = await file.stat();
            if (!stat.isFile() || stat.size > 16_384) throw new GuardError("inventory");
            const bytes = Buffer.alloc(16_385);
            const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
            if (bytesRead > 16_384) throw new GuardError("inventory");
            token = bytes.subarray(0, bytesRead).toString("utf8").trim();
          } finally {
            await file.close();
          }
        }
        add(token);
        const signal = AbortSignal.any([this.#controller.signal, AbortSignal.timeout(vault.timeoutMs)]);
        // Only explicitly configured KV v2 fields are loaded; never enumerate mounts or issue leases.
        for (const ref of vault.secrets) {
          const headers = new Headers({ "X-Vault-Token": token! });
          if (vault.namespace) headers.set("X-Vault-Namespace", vault.namespace);
          const response = await this.request(`${vault.address}/v1/${ref.mount}/data/${ref.path}`, {
            headers,
            signal,
            redirect: "error",
          });
          if (!response.ok) {
            void response.body?.cancel().catch(() => {});
            throw new GuardError("inventory");
          }
          const result: unknown = JSON.parse(await readText(response.body, 1024 * 1024));
          const fields = (result as { data?: { data?: Record<string, unknown> } })?.data?.data;
          if (!fields || typeof fields !== "object" || Array.isArray(fields)) throw new GuardError("inventory");
          for (const field of ref.fields) add(fields[field]);
        }
      }
      if (next.size > 1000 || [...next].reduce((total, value) => total + Buffer.byteLength(value), 0) > 2 * 1024 * 1024) {
        throw new GuardError("inventory");
      }
      if (this.#closed) throw new GuardError("inventory");
      // Keep previously observed versions so rotating a secret cannot expose it through old session history.
      this.#values = next;
      this.#expires = this.now() + (vault?.refreshMs ?? 60_000);
      return [...next];
    } catch {
      // Never expose Vault response bodies, token-file errors, paths, or credential values.
      throw new GuardError("inventory");
    }
  }

  close(): void {
    this.#closed = true;
    this.#controller.abort();
    this.#values.clear();
  }
}
