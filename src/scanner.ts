import { GuardError } from "./errors.js";

export type Detector = "known" | "pattern" | "entropy";
export type Counts = Record<Detector, number>;
export interface ScanResult { value: unknown; counts: Counts; }
interface Match { start: number; end: number; detector: Detector; }
export const REDACTED = "[REDACTED]";

// Deliberately conservative starter rules; known-value matching is the Vault-specific layer.
const patterns = [
  /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
  /\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{16,4096}\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\b(?:sk-(?:proj-|ant-api\d+-)?)[A-Za-z0-9_-]{32,512}\b/g,
  /\b(?:glpat-|xox[baprs]-|npm_)[A-Za-z0-9_-]{20,255}\b/g,
  /\bglrt-[A-Za-z0-9_-]{20,}/g,
  /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{40,}/g,
  /\bSK[a-fA-F0-9]{32}(?![A-Za-z0-9])/g,
  /\bpypi-[A-Za-z0-9_-]{50,}/g,
  /\bya29\.[A-Za-z0-9_-]+/g,
  /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,}\/B[A-Za-z0-9_]{8,}\/[A-Za-z0-9_]{24,}(?:\?[^\s"'<>)]*)?/g,
  /https:\/\/discord(?:app)?\.com\/api\/(?:v[0-9]+\/)?webhooks\/[0-9]+\/[A-Za-z0-9_-]+(?:\?[^\s"'<>)]*)?/g,
  /\b(?:sk_live_|rk_live_|AIza)[A-Za-z0-9_-]{24,255}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|$)/g,
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@[^\s"'<>]+/gi,
  /\brediss?:\/\/[^\s:/@"'<>]*:[^\s/@"'<>]+@[^\s"'<>]+/gi,
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+\/-]{8,}={0,2}/gi,
  /(?:\b|_)(?:password|passwd|token|api[_-]?key|api[_-]?secret|secret[_-]?(?:access[_-]?)?key|(?:access|session)[_-]?token)["']?\s*[:=]\s*["']?[^\s"',;}{]{8,}/gi,
];
const credentialKey = /(?:^|[_-])(?:password|passwd|token|api[_-]?key|api[_-]?secret|secret[_-]?(?:access[_-]?)?key|(?:access|session)[_-]?token)$/i;

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  return [...counts.values()].reduce((total, count) => {
    const p = count / value.length;
    return total - p * Math.log2(p);
  }, 0);
}

export class Scanner {
  readonly #known: string[];

  constructor(values: readonly string[], private readonly options: { patterns: boolean; entropy: boolean }) {
    this.#known = [...new Set(values.flatMap((value) => [
      value,
      encodeURIComponent(value),
      Buffer.from(value).toString("base64"),
      Buffer.from(value).toString("base64url"),
      JSON.stringify(value).slice(1, -1),
    ]))].filter(Boolean).sort((a, b) => b.length - a.length);
  }

  scan(input: unknown): ScanResult {
    const counts: Counts = { known: 0, pattern: 0, entropy: 0 };
    let nodes = 0;
    let matches = 0;
    const scanText = (text: string): string => {
      const ranges: Match[] = [];
      const add = (start: number, end: number, detector: Detector) => {
        if (++matches > 10_000) throw new GuardError("limit");
        ranges.push({ start, end, detector });
      };
      for (const value of this.#known) {
        let from = 0;
        while (true) {
          const index = text.indexOf(value, from);
          if (index === -1) break;
          add(index, index + value.length, "known");
          from = index + 1;
        }
      }
      if (this.options.patterns) {
        for (const pattern of patterns) {
          for (const match of text.matchAll(pattern)) add(match.index, match.index + match[0].length, "pattern");
        }
      }
      if (this.options.entropy) {
        for (const match of text.matchAll(/[A-Za-z0-9_+/=-]{24,256}/g)) {
          const token = match[0];
          if (!/^[a-f0-9]{40,64}$/i.test(token) && /[0-9]/.test(token) && /[a-z]/i.test(token) && entropy(token) >= 4.5) {
            add(match.index, match.index + token.length, "entropy");
          }
        }
      }
      ranges.sort((a, b) => a.start - b.start || b.end - a.end);
      const merged: Match[] = [];
      for (const range of ranges) {
        const previous = merged.at(-1);
        if (previous && range.start < previous.end) {
          previous.end = Math.max(previous.end, range.end);
          if (range.detector === "known") previous.detector = "known";
        } else {
          merged.push({ ...range });
        }
      }
      let result = "";
      let from = 0;
      for (const match of merged) {
        counts[match.detector]++;
        result += text.slice(from, match.start) + REDACTED;
        from = match.end;
      }
      return result + text.slice(from);
    };
    const visit = (value: unknown, depth: number): unknown => {
      if (++nodes > 100_000 || depth > 64) throw new GuardError("limit");
      if (typeof value === "string") return scanText(value);
      if (value === null || typeof value === "number" || typeof value === "boolean") return value;
      if (Array.isArray(value)) return value.map((item) => visit(item, depth + 1));
      if (value && typeof value === "object") {
        const result: Record<string, unknown> = Object.create(null);
        for (const [key, item] of Object.entries(value)) {
          const cleanKey = scanText(key);
          if (Object.hasOwn(result, cleanKey)) throw new GuardError("format");
          const before = counts.known + counts.pattern + counts.entropy;
          const clean = visit(item, depth + 1);
          if (this.options.patterns && credentialKey.test(key) && typeof item === "string" && item.length >= 8 && item !== REDACTED) {
            if (before === counts.known + counts.pattern + counts.entropy) counts.pattern++;
            result[cleanKey] = REDACTED;
          } else {
            result[cleanKey] = clean;
          }
        }
        return result;
      }
      throw new GuardError("format");
    };
    return { value: visit(input, 0), counts };
  }
}

export function matchCount(counts: Counts): number {
  return counts.known + counts.pattern + counts.entropy;
}
