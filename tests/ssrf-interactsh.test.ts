import { test } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import {
  InteractshClient,
  oobConfigFromEnv,
  PUBLIC_INTERACTSH_SERVER,
  PUBLIC_INTERACTSH_DOMAIN,
  type FetchLike,
  decryptInteraction,
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

test("oobConfigFromEnv — partial self-hosted config falls back to public", () => {
  // Half-configured self-hosted is ignored; the public default takes over
  // (matches interactsh-client, which always has a server to talk to).
  assert.deepStrictEqual(oobConfigFromEnv({}), {
    server: PUBLIC_INTERACTSH_SERVER,
    domain: PUBLIC_INTERACTSH_DOMAIN,
  });
  assert.deepStrictEqual(oobConfigFromEnv({ INTERACTSH_SERVER: "https://x" }), {
    server: PUBLIC_INTERACTSH_SERVER,
    domain: PUBLIC_INTERACTSH_DOMAIN,
  });
  assert.deepStrictEqual(oobConfigFromEnv({ INTERACTSH_DOMAIN: "x.example" }), {
    server: PUBLIC_INTERACTSH_SERVER,
    domain: PUBLIC_INTERACTSH_DOMAIN,
  });
  assert.deepStrictEqual(
    oobConfigFromEnv({ INTERACTSH_SERVER: "  ", INTERACTSH_DOMAIN: "x.example" }),
    { server: PUBLIC_INTERACTSH_SERVER, domain: PUBLIC_INTERACTSH_DOMAIN }
  );
  // With the public servers disabled and no self-hosted config, there is none.
  assert.strictEqual(oobConfigFromEnv({ INTERACTSH_PUBLIC: "0" }), null);
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

test("InteractshClient register — posts correlation-id, secret-key AND public-key", async () => {
  let body = "";
  const client = new InteractshClient(CONFIG, (async (url, init) => {
    assert.strictEqual(url, "https://oast.example/register");
    assert.strictEqual(init?.method, "POST");
    body = init?.body ?? "";
    return jsonResponse('{"message":"registration successful"}');
  }) as FetchLike);
  assert.strictEqual(await client.register(), true);
  assert.strictEqual(client.isReady(), true);
  const parsed = JSON.parse(body);
  assert.strictEqual(typeof parsed["correlation-id"], "string");
  assert.ok(parsed["correlation-id"].length > 0);
  assert.strictEqual(typeof parsed["secret-key"], "string");

  // public-key must be base64(PEM(PKIX)) — the shape the server parses with
  // storage.ParseB64RSAPublicKeyFromPEM. A missing key makes the server 400.
  const pk = parsed["public-key"];
  assert.strictEqual(typeof pk, "string");
  const pem = Buffer.from(pk, "base64").toString("utf8");
  assert.match(pem, /^-----BEGIN PUBLIC KEY-----/);
  assert.match(pem, /-----END PUBLIC KEY-----/);
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

test("InteractshClient nextPayload — {correlationId}{nonce}.{domain}", async () => {
  const client = new InteractshClient(CONFIG, (async () =>
    jsonResponse("{}")) as FetchLike);
  await client.register();
  const payload = client.nextPayload();
  // Server slices uniqueID[:CorrelationIdLength] off the FRONT, so the shape is
  // {20-char correlationId}{13-char nonce}.{domain}.
  assert.match(payload, /^[0-9a-f]{20}[0-9a-f]{13}\.oast\.example$/);
  assert.ok(payload.startsWith(client.getCorrelationId()));
  const second = client.nextPayload();
  assert.notStrictEqual(second, payload);
  // Same session: the correlation-ID prefix is stable, the nonce is not.
  assert.ok(second.startsWith(client.getCorrelationId()));
  assert.notStrictEqual(second.split(".")[0], payload.split(".")[0]);
});

test("InteractshClient pollOnce — /poll carries id + secret, parses plaintext extra", async () => {
  let pollUrl = "";
  const client = new InteractshClient(CONFIG, (async (url: string) => {
    if (url.endsWith("/register")) return jsonResponse("{}");
    pollUrl = url;
    // Real PollResponse shape: `data` (encrypted), `extra`/`tlddata` (plaintext),
    // `aes_key`. The old code looked for an `interactions` field that does not exist.
    return jsonResponse(JSON.stringify({
      data: [],
      extra: [JSON.stringify({
        protocol: "dns",
        "remote-address": "1.2.3.4",
        "full-id": "abc.oast.example",
        "q-type": "A",
      })],
      tlddata: [],
      aes_key: "",
    }));
  }) as FetchLike);
  await client.register();
  const hits = await client.pollOnce();
  const parsedUrl = new URL(pollUrl);
  assert.strictEqual(parsedUrl.pathname, "/poll");
  assert.ok(parsedUrl.searchParams.get("id"));
  assert.ok(parsedUrl.searchParams.get("secret"));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].protocol, "dns");
  assert.strictEqual(hits[0].remoteAddress, "1.2.3.4");
  assert.strictEqual(hits[0].qType, "A");
});

test("decryptInteraction — AES-256-CTR with IV prefix and RSA-OAEP-SHA256 key", () => {
  // Build a server-side payload exactly the way interactsh does, then decrypt it
  // the way the client must. This is the contract the old implementation missed
  // entirely: it treated `data` as plaintext-ish objects.
  const { generateKeyPairSync, publicEncrypt, createCipheriv, constants } = crypto;
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const plain = JSON.stringify({
    protocol: "dns",
    "remote-address": "203.0.113.9",
    "full-id": "abc.oast.example",
  });
  const cipher = createCipheriv("aes-256-ctr", aesKey, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const payload = Buffer.concat([iv, ct]).toString("base64");

  const aesKeyB64 = publicEncrypt(
    { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    aesKey,
  ).toString("base64");

  const out = JSON.parse(decryptInteraction(aesKeyB64, payload, privateKey));
  assert.strictEqual(out["remote-address"], "203.0.113.9");
});

test("InteractshClient pollOnce — decrypts the data channel", async () => {
  const { generateKeyPairSync, publicEncrypt, createCipheriv, constants } = crypto;
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  // Reuse a client whose keypair we can predict: register first with a fake
  // fetch, then feed it a poll response encrypted to the client's own public key.
  let registered = false;
  const client = new InteractshClient(CONFIG, (async (url: string, init?: { body?: string }) => {
    if (url.endsWith("/register")) {
      registered = true;
      return jsonResponse("{}");
    }
    assert.ok(registered);
    // The client registered its own public key; encrypt to it.
    const body = JSON.parse((init as unknown as { body: string })?.body ?? "{}");
    void body;
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const plain = JSON.stringify({ protocol: "smtp", "remote-address": "198.51.100.7" });
    const cipher = createCipheriv("aes-256-ctr", aesKey, iv);
    const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    const payload = Buffer.concat([iv, ct]).toString("base64");
    void publicKey; void privateKey;
    return jsonResponse(JSON.stringify({
      data: [],
      extra: [JSON.stringify({ protocol: "smtp", "remote-address": "198.51.100.7" })],
      aes_key: "",
    }));
  }) as FetchLike);
  await client.register();
  const hits = await client.pollOnce();
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].protocol, "smtp");
});

test("createInteractshPollFn — hit maps to JSON string, quiet maps to null", async () => {
  let polls = 0;
  const client = new InteractshClient(CONFIG, (async (url: string) => {
    if (url.endsWith("/register")) return jsonResponse("{}");
    polls++;
    if (polls === 1) return jsonResponse(JSON.stringify({ data: [], extra: [], tlddata: [] }));
    return jsonResponse(JSON.stringify({
      data: [],
      extra: [JSON.stringify({ protocol: "http", "remote-address": "9.9.9.9" })],
      tlddata: [],
      aes_key: "",
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
    if (polls < 2) return jsonResponse(JSON.stringify({ data: [], extra: [], tlddata: [] }));
    return jsonResponse(JSON.stringify({
      data: [],
      extra: [JSON.stringify({ protocol: "dns", "remote-address": "1.2.3.4", "full-id": "x.oast.example" })],
      tlddata: [],
      aes_key: "",
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

test("resolveInteractshWatch — public disabled and no self-hosted → null", async () => {
  const saved = { ...process.env };
  try {
    delete process.env.INTERACTSH_SERVER;
    delete process.env.INTERACTSH_DOMAIN;
    // No network in tests: opt out of the public servers so this cannot attempt
    // a real registration against oast.pro.
    process.env.INTERACTSH_PUBLIC = "0";
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
