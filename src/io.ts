import { GuardError } from "./errors.js";

export async function readText(body: ReadableStream<Uint8Array> | null, limit: number): Promise<string> {
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > limit) throw new GuardError("limit");
      chunks.push(chunk.value);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  } catch (error) {
    void reader.cancel().catch(() => {});
    throw error instanceof GuardError ? error : new GuardError("format");
  } finally {
    reader.releaseLock();
  }
}
