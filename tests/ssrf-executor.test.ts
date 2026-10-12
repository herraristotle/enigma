import { test } from "node:test";
import assert from "node:assert";
import http from "node:http";
import { executeSsrfPlan, type SsrfExecutionOutcome } from "../core/engines/ssrf/executor.ts";
import { NotificationManager, type ScanResult, type NotificationChannel } from "../core/engines/ssrf/canary.ts";
import type { SsrfPayload } from "../core/engines/ssrf/decision-trees.ts";

class CapturingChannel implements NotificationChannel {
  sent: ScanResult[] = [];
  async send(result: ScanResult): Promise<void> {
    this.sent.push(result);
  }
}

interface ServerHarness {
  server: http.Server;
  port: number;
  requests: Array<{ url: string; headers: http.IncomingHttpHeaders }>;
  close: () => Promise<void>;
}

async function startServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void
): Promise<ServerHarness> {
  const requests: ServerHarness["requests"] = [];
  const server = http.createServer((req, res) => {
    requests.push({ url: req.url ?? "", headers: req.headers });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return {
    server,
    port: address.port,
    requests,
    close: () => new Promise((resolve) => server.close(() => resolve()))
  };
}

function plan(...payloads: SsrfPayload[]): SsrfPayload[] {
  return payloads;
}

test("executor injects payload as parameter and classifies no_signal", async () => {
  const harness = await startServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<html>benign</html>");
  });
  try {
    const outcome = await executeSsrfPlan(
      `http://127.0.0.1:${harness.port}/fetch`,
      "url",
      plan({ category: "localhost admin", payload: "http://localhost/admin", technique: "direct" }),
      { notifications: new NotificationManager() }
    );
    assert.strictEqual(outcome.results.length, 1);
    assert.strictEqual(outcome.results[0].status, "no_signal");
    assert.strictEqual(harness.requests.length, 1);
    const seen = new URL(harness.requests[0].url, "http://x");
    assert.strictEqual(seen.searchParams.get("url"), "http://localhost/admin");
  } finally {
    await harness.close();
  }
});

test("executor confirms on high-confidence content match, attaches CVSS, notifies", async () => {
  const harness = await startServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end('{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}');
  });
  const channel = new CapturingChannel();
  const manager = new NotificationManager();
  manager.addChannel(channel);
  try {
    const outcome: SsrfExecutionOutcome = await executeSsrfPlan(
      `http://127.0.0.1:${harness.port}/fetch`,
      "url",
      plan(
        { category: "cloud metadata", payload: "http://169.254.169.254/latest/meta-data/", technique: "direct" },
        { category: "localhost admin", payload: "http://localhost/never-reached", technique: "direct" }
      ),
      { notifications: manager }
    );
    assert.strictEqual(outcome.confirmed, 1);
    // Hard confirmation stops the scan — second payload never sent.
    assert.strictEqual(harness.requests.length, 1);
    assert.strictEqual(outcome.results[0].status, "confirmed");
    assert.ok(outcome.results[0].cvss, "confirmed result must carry CVSS");
    assert.ok(outcome.results[0].cvss!.base >= 8, "cloud metadata must score high");
    assert.strictEqual(channel.sent.length, 1);
    assert.strictEqual(channel.sent[0].status, "confirmed");
  } finally {
    await harness.close();
  }
});

test("executor maps 403 to blocked and advances state machine", async () => {
  const harness = await startServer((_req, res) => {
    res.writeHead(403);
    res.end("forbidden");
  });
  try {
    const outcome = await executeSsrfPlan(
      `http://127.0.0.1:${harness.port}/fetch`,
      "url",
      plan(
        { category: "internal service", payload: "http://127.0.0.1:6379/", technique: "direct" },
        { category: "internal service", payload: "http://127.0.0.1:9200/", technique: "direct" }
      ),
      { notifications: new NotificationManager() }
    );
    assert.strictEqual(outcome.confirmed, 0);
    assert.ok(outcome.results.every((r) => r.status === "blocked"));
    assert.ok(outcome.attempts >= 1);
    assert.notStrictEqual(outcome.phase, "report");
  } finally {
    await harness.close();
  }
});

test("executor honors timeout and records error status", async () => {
  const harness = await startServer(() => {
    // Never respond — client must time out.
  });
  try {
    const started = Date.now();
    const outcome = await executeSsrfPlan(
      `http://127.0.0.1:${harness.port}/fetch`,
      "url",
      plan({ category: "localhost admin", payload: "http://localhost/admin" }),
      { notifications: new NotificationManager(), timeoutMs: 200, maxAttempts: 1 }
    );
    const elapsed = Date.now() - started;
    assert.strictEqual(outcome.results[0].status, "error");
    assert.ok(elapsed < 5000, `timeout must be honored (took ${elapsed}ms)`);
  } finally {
    await harness.close();
  }
});

test("executor forwards plan-supplied headers", async () => {
  const harness = await startServer((_req, res) => {
    res.writeHead(200);
    res.end("ok");
  });
  try {
    await executeSsrfPlan(
      `http://127.0.0.1:${harness.port}/fetch`,
      "url",
      plan({
        category: "header injection",
        payload: "http://169.254.169.254/",
        technique: "X-Forwarded-For",
        headers: { "x-forwarded-for": "127.0.0.1" }
      }),
      { notifications: new NotificationManager(), maxAttempts: 1 }
    );
    assert.strictEqual(harness.requests[0].headers["x-forwarded-for"], "127.0.0.1");
  } finally {
    await harness.close();
  }
});

test("executor validates inputs", async () => {
  await assert.rejects(() => executeSsrfPlan("", "url", []), TypeError);
  await assert.rejects(() => executeSsrfPlan("http://x", "", []), TypeError);
});

test("blind plan with no confirmation attaches statistical timing + size analysis", async () => {
  const harness = await startServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("benign response");
  });
  try {
    const outcome = await executeSsrfPlan(
      `http://127.0.0.1:${harness.port}/fetch`,
      "url",
      plan(
        { category: "internal service", payload: "http://10.0.0.1/admin", technique: "direct" },
        { category: "internal service", payload: "http://192.168.1.1/", technique: "direct" },
        { category: "external service", payload: "http://example.com/", technique: "direct" },
        { category: "external service", payload: "http://example.org/", technique: "direct" }
      ),
      { notifications: new NotificationManager(), timeoutMs: 3000 }
    );
    assert.strictEqual(outcome.confirmed, 0, "expect blind (no direct confirmation)");
    assert.ok(outcome.statistical, "blind fallback must attach statistical analysis");
    const { timing, sizes } = outcome.statistical;
    assert.ok(typeof timing.mean === "number");
    assert.ok(typeof timing.stdDev === "number");
    assert.ok(Array.isArray(timing.outliers));
    assert.ok(Array.isArray(timing.timeouts));
    assert.ok(sizes.confidence === "high" || sizes.confidence === "medium" || sizes.confidence === "low");
    assert.ok(typeof sizes.difference === "number");
    assert.ok(Array.isArray(sizes.anomalies));
  } finally {
    await harness.close();
  }
});
