export interface SecretRef {
  mount: string;
  path: string;
  fields: string[];
}

export interface VaultConfig {
  address: string;
  namespace?: string;
  tokenEnv: string;
  tokenFile?: string;
  secrets: SecretRef[];
  refreshMs: number;
  timeoutMs: number;
}

export interface Config {
  mode: "redact" | "block";
  env: string[];
  patterns: boolean;
  entropy: boolean;
  maxBodyBytes: number;
  metricsPort?: number;
  vault?: VaultConfig;
}

function invalid(): never {
  // Configuration may contain credentials; never interpolate rejected values.
  throw new Error("Vault Guard: invalid configuration; see the documented options.");
}

function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const result = value as Record<string, unknown>;
  if (Object.keys(result).some((key) => !keys.includes(key))) invalid();
  return result;
}

function text(value: unknown): string {
  if (typeof value !== "string" || !value || value.length > 4096) invalid();
  return value;
}

function number(value: unknown, fallback: number, min: number, max: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) invalid();
  return value;
}

function flag(value: unknown, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") invalid();
  return value;
}

function strings(value: unknown, max = 100): string[] {
  if (!Array.isArray(value) || value.length > max) invalid();
  return value.map(text);
}

function envName(value: unknown): string {
  const result = text(value);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(result)) invalid();
  return result;
}

function path(value: unknown): string {
  const result = text(value);
  if (result.split("/").some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) invalid();
  return result;
}

export function parseConfig(input: unknown, env = process.env): Config {
  const value = object(input, ["mode", "env", "patterns", "entropy", "maxBodyBytes", "metricsPort", "vault"]);
  if (value.mode !== undefined && value.mode !== "redact" && value.mode !== "block") invalid();
  const config: Config = {
    mode: value.mode ?? "redact",
    env: strings(value.env ?? []).map(envName),
    patterns: flag(value.patterns, true),
    entropy: flag(value.entropy, false),
    maxBodyBytes: number(value.maxBodyBytes, 4 * 1024 * 1024, 1024, 16 * 1024 * 1024),
  };
  if (value.metricsPort !== undefined) config.metricsPort = number(value.metricsPort, 0, 0, 65535);
  if (value.vault !== undefined) {
    const vault = object(value.vault, ["address", "namespace", "tokenEnv", "tokenFile", "secrets", "refreshMs", "timeoutMs"]);
    let address: URL;
    try {
      address = new URL(text(vault.address ?? env.VAULT_ADDR));
    } catch {
      invalid();
    }
    const loopback = ["127.0.0.1", "[::1]", "localhost"].includes(address.hostname);
    if (address.protocol !== "https:" && !(address.protocol === "http:" && loopback)) invalid();
    if (address.username || address.password || address.search || address.hash || address.pathname !== "/") invalid();
    if (!Array.isArray(vault.secrets) || vault.secrets.length === 0 || vault.secrets.length > 100) invalid();
    config.vault = {
      address: address.origin,
      tokenEnv: envName(vault.tokenEnv ?? "VAULT_TOKEN"),
      secrets: vault.secrets.map((item) => {
        const ref = object(item, ["mount", "path", "fields"]);
        const fields = strings(ref.fields);
        if (!fields.length) invalid();
        return { mount: path(ref.mount), path: path(ref.path), fields };
      }),
      refreshMs: number(vault.refreshMs, 60_000, 1000, 300_000),
      timeoutMs: number(vault.timeoutMs, 3000, 100, 10_000),
    };
    if (vault.namespace !== undefined || env.VAULT_NAMESPACE) {
      config.vault.namespace = path(vault.namespace ?? env.VAULT_NAMESPACE);
    }
    if (vault.tokenFile !== undefined) {
      config.vault.tokenFile = text(vault.tokenFile);
      if (!config.vault.tokenFile.startsWith("/")) invalid();
    }
  }
  if (!config.patterns && !config.entropy && !config.env.length && !config.vault) invalid();
  return config;
}
