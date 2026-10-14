import type { Config } from "./config.js";
import { GuardError, reason } from "./errors.js";
import { Inventory } from "./inventory.js";
import { readText } from "./io.js";
import { Metrics } from "./metrics.js";
import type { Surface } from "./metrics.js";
import { matchCount, Scanner } from "./scanner.js";
import type { ScanResult } from "./scanner.js";

export const BLOCKED = "[VAULT GUARD] Content withheld because safe inspection could not be completed.";
export const BLOCKED_FRAME = '{"type":"vault_guard.blocked"}';

function rejectMedia(value: unknown, depth = 0): void {
  if (depth > 64) throw new GuardError("limit");
  if (typeof value === "string" && /^data:(?!text\/plain[;,])/i.test(value)) throw new GuardError("format");
  if (!value || typeof value !== "object") return;
  const object = value as Record<string, unknown>;
  if (typeof object.type === "string" && ["image", "image_url", "input_image", "audio", "input_audio", "document", "file", "input_file", "video"].includes(object.type)) {
    throw new GuardError("format");
  }
  if (Object.hasOwn(object, "inlineData") || Object.hasOwn(object, "fileData") || Object.hasOwn(object, "inline_data") || Object.hasOwn(object, "file_data")) {
    throw new GuardError("format");
  }
  for (const child of Object.values(value)) rejectMedia(child, depth + 1);
}

export class Guard {
  constructor(
    readonly config: Config,
    readonly inventory = new Inventory(config),
    readonly metrics = new Metrics(),
  ) {}

  private async inspect(value: unknown, surface: Surface): Promise<ScanResult> {
    const scanner = new Scanner(await this.inventory.values(), this.config);
    const result = scanner.scan(value);
    if (matchCount(result.counts)) {
      this.metrics.prevented(surface, this.config.mode, result.counts);
      if (this.config.mode === "block") throw new GuardError("secret");
    }
    return result;
  }

  private async json(text: string, surface: Surface): Promise<string> {
    if (Buffer.byteLength(text) > this.config.maxBodyBytes) throw new GuardError("limit");
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new GuardError("format");
    }
    rejectMedia(value);
    const result = await this.inspect(value, surface);
    return matchCount(result.counts) ? JSON.stringify(result.value) : text;
  }

  async http(event: { request: Request }): Promise<void> {
    const original = event.request;
    if (!original.body) return;
    this.metrics.scanned("http");
    // Install a safe failure state before any asynchronous work. Host hook errors need not be fail-closed.
    event.request = new Request("https://vault-guard.invalid/blocked", {
      method: "POST",
      body: "{}",
      signal: AbortSignal.abort(new Error(BLOCKED)),
    });
    try {
      const type = original.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
      if (!(type === "application/json" || type?.endsWith("+json")) || original.headers.has("content-encoding")) {
        throw new GuardError("format");
      }
      const text = await readText(original.body, this.config.maxBodyBytes);
      const body = await this.json(text, "http");
      const headers = new Headers(original.headers);
      headers.delete("content-length");
      // Headers contain intentional provider authentication and are outside the content filter.
      event.request = new Request(original, { body, headers });
    } catch (error) {
      this.metrics.blocked("http", reason(error));
    }
  }

  async websocket(event: { frame: string }): Promise<void> {
    const original = event.frame;
    event.frame = BLOCKED_FRAME;
    this.metrics.scanned("websocket");
    try {
      event.frame = await this.json(original, "websocket");
    } catch (error) {
      this.metrics.blocked("websocket", reason(error));
    }
  }

  async tool(value: unknown): Promise<unknown> {
    this.metrics.scanned("tool");
    try {
      const serialized = JSON.stringify(value);
      if (typeof serialized !== "string" || Buffer.byteLength(serialized) > this.config.maxBodyBytes) throw new GuardError("limit");
      return (await this.inspect(JSON.parse(serialized), "tool")).value;
    } catch (error) {
      this.metrics.blocked("tool", reason(error));
      return { content: BLOCKED };
    }
  }

  close(): void {
    this.inventory.close();
  }
}
