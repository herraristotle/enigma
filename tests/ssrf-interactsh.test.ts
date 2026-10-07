import { test } from "node:test";
import assert from "node:assert";
import {
  InteractshClient,
  oobConfigFromEnv,
  type FetchLike,
} from "../core/engines/ssrf/interactsh.ts";
import {
  createInteractshPollFn,
  resolveInteractshWatch,
  watchForCallbacks,
} from "../cli/commands/ssrf/blind.ts";
import { NotificationManager, type ScanResult } from "../core/engines/ssrf/canary.ts";

function jsonResponse(body: string, ok = true, status = 200) {
  return { ok, status, text: async () => body };
}

function capturingManager(received: ScanResult[]): NotificationManager {
  const manager = new NotificationManager();
  manager.addChannel({ async send(r: ScanResult) { received.push(r); } });
  return manager;
}

const CONFIG = { server: "https://oast.example", domain: "oast.example" };

test("oobConfigFromEnv — missing server or domain → null", () => {
  assert.strictEqual(oobConfigFromEnv({}), null);
  assert.strictEqual(oobConfigFromEnv({ INTERACTSH_SERVER: "https://x" }), null);
  assert.strictEqual(oobConfigFromEnv({ INTERACTSH_DOMAIN: "x.example" }), null);
  assert.strictEqual(
    oobConfigFromEnv({ INTERACTSH_SERVER: "  ", INTERACTSH_DOMAIN: "x.example" }),
    null
  );
});

test("oobConfigFromEnv — all three set → config with token", () => {
  const cfg = oobConfigFromEnv({
    INTERACTSH_SERVER: "https://oast.example",
    INTERACTSH_DOMAIN: "oast.example",
    INTERACTSH_TOKEN: "sekrit",
  });
  assert.deepStrictEqual(cfg, {
    server: "https://oast.example",
    domain: "oast.example",
    token: "sekrit",
  });
});

test("InteractshClient register — posts correlation-id, becomes ready", async () => {
  let body = "";
  const client = new InteractshClient(CONFIG, (async (url, init) => {
    assert.strictEqual(url, "https://oast.example/register");
    assert.strictEqual(init?.method, "POST");
    body = init?.body ?? "";
    return jsonResponse("{}");
  }) as FetchLike);
  assert.strictEqual(await client.register(), true);
  assert.strictEqual(client.isReady(), true);
  const parsed = JSON.parse(body);
  assert.strictEqual(typeof parsed["correlation-id"], "string");
  assert.ok(parsed["correlation-id"].length > 0);
});

test("InteractshClient register failure — self-disables, poll/wait no-ops", async () => {
  const client = new InteractshClient(CONFIG, (async () =>
    jsonResponse("nope", false, 403)) as FetchLike);
  assert.strictEqual(await client.register(), false);
  assert.strictEqual(client.isReady(), false);
  assert.deepStrictEqual(await client.pollOnce(), []);
  assert.strictEqual(await client.waitForInteraction(50, 10), null);
  // Stays disabled — second register attempt without another fetch.
  assert.strictEqual(await client.register(), false);
});

test("InteractshClient nextPayload — {label}.{correlationId}.{domain}", async () => {
  const client = new InteractshClient(CONFIG, (async () =>
    jsonResponse("{}")) as FetchLike);
  await client.register();
  const payload = client.nextPayload();
  assert.match(payload, /^[0-9a-f]{13}\.[0-9a-f-]{36}\.oast\.example$/);
  const second = client.nextPayload();
  assert.notStrictEqual(second, payload);
  assert.strictEqual(second.split(".")[1], payload.split(".")[1]);
});

test("InteractshClient pollOnce — interactions URL carries id + secret, parses entries", async () => {
  let pollUrl = "";
  const client = new InteractshClient(CONFIG, (async (url: string) => {
    if (url.endsWith("/register")) return jsonResponse("{}");
    pollUrl = url;
    return jsonResponse(JSON.stringify({
      interactions: [
        { protocol: "dns", "remote-address": "1.2.3.4", "full-id": "abc.oast.example" },
      ],
    }));
  }) as FetchLike);
  await client.register();
  const hits = await client.pollOnce();
  const parsedUrl = new URL(pollUrl);
  assert.strictEqual(parsedUrl.pathname, "/interactions");
  assert.ok(parsedUrl.searchParams.get("id"));
  assert.ok(parsedUrl.searchParams.get("secret"));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].protocol, "dns");
  assert.strictEqual(hits[0].remoteAddress, "1.2.3.4");
});

test("createInteractshPollFn — hit maps to JSON string, quiet maps to null", async () => {
  let polls = 0;
  const client = new InteractshClient(CONFIG, (async (url: string) => {
    if (url.endsWith("/register")) return jsonResponse("{}");
    polls++;
    if (polls === 1) return jsonResponse("[]");
    return jsonResponse(JSON.stringify({
      interactions: [{ protocol: "http", "remote-address": "9.9.9.9" }],
    }));
  }) as FetchLike);
  await client.register();
  const pollFn = createInteractshPollFn(client);
  assert.strictEqual(await pollFn("http://canary.test/poll"), null);
  const body = await pollFn("http://canary.test/poll");
  assert.ok(body);
  const parsed = JSON.parse(body!);
  assert.strictEqual(parsed[0].protocol, "http");
});

test("createInteractshPollFn — disabled client → null (never throws)", async () => {
  const client = new InteractshClient(CONFIG, (async () =>
    jsonResponse("", false, 500)) as FetchLike);
  await client.register();
  const pollFn = createInteractshPollFn(client);
  assert.strictEqual(await pollFn("http://canary.test/poll"), null);
});

test("adapter feeds watchForCallbacks — confirmed result, notify once", async () => {
  const received: ScanResult[] = [];
  let polls = 0;
  const client = new InteractshClient(CONFIG, (async (url: string) => {
    if (url.endsWith("/register")) return jsonResponse("{}");
    polls++;
    if (polls < 2) return jsonResponse("[]");
    return jsonResponse(JSON.stringify({
      interactions: [{ protocol: "dns", "remote-address": "1.2.3.4" }],
    }));
  }) as FetchLike);
  await client.register();

  const result = await watchForCallbacks("http://oob-only/payload", {
    targetUrl: "https://victim.test/fetch",
    parameter: "url",
    notifications: capturingManager(received),
    timeoutMs: 2000,
    intervalMs: 10,
    pollFn: createInteractshPollFn(client),
  });

  assert.ok(result, "watch should return a confirmed result");
  assert.strictEqual(result!.status, "confirmed");
  assert.strictEqual(result!.confirmationLevel, "confirmed");
  assert.strictEqual(received.length, 1, "notification fires exactly once");
});

test("watchForCallbacks — disabled adapter → timeout null, zero notifications", async () => {
  const received: ScanResult[] = [];
  const client = new InteractshClient(CONFIG, (async () =>
    jsonResponse("", false, 500)) as FetchLike);
  await client.register();

  const result = await watchForCallbacks("http://oob-only/payload", {
    notifications: capturingManager(received),
    timeoutMs: 45,
    intervalMs: 15,
    pollFn: createInteractshPollFn(client),
  });

  assert.strictEqual(result, null);
  assert.strictEqual(received.length, 0);
});

test("resolveInteractshWatch — no env → null", async () => {
  const saved = { ...process.env };
  try {
    delete process.env.INTERACTSH_SERVER;
    delete process.env.INTERACTSH_DOMAIN;
    assert.strictEqual(await resolveInteractshWatch("http://canary.test/c/x"), null);
  } finally {
    process.env = saved;
  }
});

test("resolveInteractshWatch — register failure → null", async () => {
  // No network in tests: unreachable localhost server forces register() failure.
  const saved = { ...process.env };
  try {
    process.env.INTERACTSH_SERVER = "http://127.0.0.1:1";
    process.env.INTERACTSH_DOMAIN = "oast.example";
    assert.strictEqual(await resolveInteractshWatch(), null);
  } finally {
    process.env = saved;
  }
});
