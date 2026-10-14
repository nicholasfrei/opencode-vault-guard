export type BlockReason = "inventory" | "format" | "limit" | "secret" | "internal";

export class GuardError extends Error {
  constructor(readonly reason: BlockReason) {
    super(`Vault Guard blocked content (${reason}).`);
    this.name = "GuardError";
  }
}

export function reason(error: unknown): BlockReason {
  return error instanceof GuardError ? error.reason : "internal";
}
