// Support for live-vault.ts only. Never logs request bodies, headers, or credentials.
import { Plugin } from "@opencode/plugin";
import { readFileSync, writeFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

type Options = {
  evidence: string;
  fixture: string;
  grepFixture: string;
  needles: string;
  real: boolean;
  fakeOrigin: string;
  replacedPlugin: string;
  requiredPlugins: string[];
};
type Evidence = {
  beforeHttp: number;
  afterHttp: number;
  responses: number;
  responseSuccesses: number;
  inputCanaries: number;
  survivingCanaries: number;
  markers: number;
  toolMarkers: number;
  toolErrors: number;
  toolCalls: Record<string, number>;
  guardMs: number[];
  requestMs: number[];
  responseStatuses: number[];
  toolMs: number[];
  oldAbsent: boolean;
  newActive: boolean;
  realPluginsActive: boolean;
  probeOrderCorrect: boolean;
  authPreserved: boolean;
  authPresent: boolean;
  unexpectedTransport: boolean;
  assertionFailed: boolean;
};
type Shared = {
  evidence: Evidence;
  requests: Map<string, { start: number; sent?: number; auth: string | null }>;
  tools: Map<string, number>;
};
const key = Symbol.for("vault.guard.live.probe");
const globalStore = globalThis as typeof globalThis & { [key]?: Shared };
const marker = "[REDACTED]";

export function strings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(strings);
  if (value && typeof value === "object") return Object.entries(value).flatMap(([k, v]) => [k, ...strings(v)]);
  return [];
}

function state(): Shared {
  return globalStore[key] ??= {
    requests: new Map(), tools: new Map(),
    evidence: {
      beforeHttp: 0, afterHttp: 0, responses: 0, responseSuccesses: 0,
      inputCanaries: 0, survivingCanaries: 0, markers: 0, toolMarkers: 0,
      toolErrors: 0, toolCalls: {}, guardMs: [], requestMs: [], responseStatuses: [], toolMs: [],
      oldAbsent: false, newActive: false, realPluginsActive: false,
      probeOrderCorrect: false, authPreserved: true, authPresent: false,
      unexpectedTransport: false, assertionFailed: false,
    },
  };
}

function save(options: Options) {
  writeFileSync(options.evidence, JSON.stringify(state().evidence), { mode: 0o600 });
}

export const before = Plugin.define({
  id: "vault.guard.live.before",
  async setup(ctx) {
    const options = ctx.options as unknown as Options;
    const needles: string[] = JSON.parse(readFileSync(options.needles, "utf8"));
    const shared = state();
    await ctx.session.hook("title", (event) => { event.result = "Vault Guard synthetic trial"; });
    await ctx.session.hook("retry", (event) => { event.decision = { retry: false }; });
    await ctx.session.hook("http.request", async (event) => {
      shared.evidence.beforeHttp++;
      const list = await ctx.plugin.list();
      const plugins = Array.isArray(list) ? list : list.data;
      const active = (id: string) => plugins.some((p) => p.id === id && p.state.status === "active");
      shared.evidence.oldAbsent = !active(options.replacedPlugin);
      shared.evidence.newActive = active("vault.guard");
      shared.evidence.realPluginsActive = options.requiredPlugins.every(active);
      const index = (id: string) => plugins.findIndex((p) => p.id === id);
      shared.evidence.probeOrderCorrect = index("vault.guard.live.before") < index("vault.guard") && index("vault.guard") < index("vault.guard.live.after");
      const record = { start: 0, auth: event.request.headers.get("authorization") };
      shared.requests.set(`${event.sessionID}:${event.kind}`, record);
      if (event.request.body) {
        const body = JSON.parse(await event.request.clone().text());
        const text = strings(body);
        shared.evidence.inputCanaries += needles.filter((n) => text.some((s) => s.includes(n))).length;
      }
      // Inventory/provider credentials are never copied into evidence.
      save(options);
      if (!shared.evidence.oldAbsent || !shared.evidence.newActive || !shared.evidence.realPluginsActive || !shared.evidence.probeOrderCorrect) {
        shared.evidence.assertionFailed = true; save(options);
        throw new Error("Live trial plugin state assertion failed");
      }
      record.start = performance.now();
    });
    await ctx.tool.hook("execute.before", (event) => {
      const input = event.input as Record<string, unknown>;
      const tool = event.tool;
      const allowed = tool === "guard_live_fixture"
        || (tool === "read" && input.path === options.fixture)
        || (tool === "grep" && input.path === options.grepFixture && input.pattern === "SYNTHETIC_CANARY")
        || (tool === "shell" && input.command === `cat -- '${options.fixture}'`);
      if (!allowed || Object.values(shared.evidence.toolCalls).reduce((a, b) => a + b, 0) >= 6) {
        shared.evidence.assertionFailed = true; save(options);
        throw new Error("Live trial tool scope assertion failed");
      }
      shared.tools.set(event.id, performance.now());
      shared.evidence.toolCalls[tool] = (shared.evidence.toolCalls[tool] ?? 0) + 1;
      save(options);
    });
  },
});

export const after = Plugin.define({
  id: "vault.guard.live.after",
  async setup(ctx) {
    const options = ctx.options as unknown as Options;
    const needles: string[] = JSON.parse(readFileSync(options.needles, "utf8"));
    const shared = state();
    await ctx.tool.transform((editor) => {
      for (const tool of editor.list()) {
        if (!["read", "shell", "grep"].includes(tool.id) || options.real) editor.remove(tool.id);
        else editor.update(tool.id, (draft) => { draft.options = { namespace: draft.options?.namespace, permission: draft.options?.permission, codemode: false }; });
      }
      editor.add({
        name: "guard_live_fixture", description: "Return the local synthetic validation fixture once.",
        input: { type: "object", properties: {}, additionalProperties: false },
        options: { codemode: false },
        execute: async () => ({ content: readFileSync(options.fixture, "utf8") }),
      });
    });
    await ctx.session.hook("context", (event) => {
      for (const name of Object.keys(event.tools)) {
        if (!(options.real ? ["guard_live_fixture"] : ["read", "shell", "grep", "guard_live_fixture"]).includes(name)) delete event.tools[name];
      }
      event.options.maxTokens = 512;
    });
    await ctx.session.hook("experimental.ws.handshake", () => {
      shared.evidence.unexpectedTransport = true; shared.evidence.assertionFailed = true; save(options);
      throw new Error("Live trial requires HTTP transport");
    });
    await ctx.session.hook("http.request", async (event) => {
      const record = shared.requests.get(`${event.sessionID}:${event.kind}`);
      shared.evidence.afterHttp++;
      if (!record) { shared.evidence.assertionFailed = true; save(options); throw new Error("Live trial missing leading hook"); }
      shared.evidence.guardMs.push(performance.now() - record.start);
      const destination = new URL(event.request.url);
      if (options.real ? destination.protocol !== "https:" || !(destination.hostname === "api.githubcopilot.com" || destination.hostname.endsWith(".githubcopilot.com")) : destination.origin !== options.fakeOrigin) {
        shared.evidence.assertionFailed = true; save(options);
        throw new Error("Live trial destination assertion failed");
      }
      shared.evidence.authPreserved &&= record.auth === event.request.headers.get("authorization");
      shared.evidence.authPresent ||= Boolean(record.auth);
      const parsed = JSON.parse(await event.request.clone().text());
      const text = strings(parsed);
      const survivors = needles.filter((n) => text.some((s) => s.includes(n))).length;
      shared.evidence.survivingCanaries += survivors;
      shared.evidence.markers += text.reduce((total, s) => total + s.split(marker).length - 1, 0);
      record.sent = performance.now();
      save(options);
      if (survivors || !shared.evidence.authPreserved || shared.evidence.afterHttp > 8) {
        shared.evidence.assertionFailed = true; save(options);
        throw new Error("Live trial outbound assertion failed");
      }
    });
    await ctx.session.hook("http.response", (event) => {
      const record = shared.requests.get(`${event.sessionID}:${event.kind}`);
      shared.evidence.responses++;
      shared.evidence.responseStatuses.push(event.response.status);
      if (event.response.ok) shared.evidence.responseSuccesses++;
      if (record?.sent !== undefined) shared.evidence.requestMs.push(performance.now() - record.sent);
      save(options);
    });
    await ctx.tool.hook("execute.after", (event) => {
      const start = shared.tools.get(event.id);
      if (start !== undefined) shared.evidence.toolMs.push(performance.now() - start);
      if (event.status !== "completed") shared.evidence.toolErrors++;
      const text = strings(event.status === "completed" ? event.result : event.error.message);
      const survivors = needles.filter((n) => text.some((s) => s.includes(n))).length;
      shared.evidence.survivingCanaries += survivors;
      shared.evidence.toolMarkers += text.reduce((total, s) => total + s.split(marker).length - 1, 0);
      save(options);
      if (survivors) {
        shared.evidence.assertionFailed = true; save(options);
        throw new Error("Live trial tool output assertion failed");
      }
    });
    save(options);
  },
});
