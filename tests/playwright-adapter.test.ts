import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import { PlaywrightBrowserAdapter } from "../core/runner/index.ts";

test("Playwright adapter injects hooks and observes a local page", async () => {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'self'",
    });
    res.end(`<html><body>${url.searchParams.get("q") ?? ""}</body></html>`);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server failed to bind");
  const adapter = new PlaywrightBrowserAdapter();

  try {
    await adapter.init();
    await adapter.injectHooks("window.__enigmaGetXssConfirmation = () => true;");
    const observation = await adapter.navigate(`http://127.0.0.1:${address.port}/`, "q", "marker");

    assert.equal(observation.statusCode, 200);
    assert.equal(observation.reflected, true);
    assert.equal(observation.executed, true);
    assert.equal(observation.cspHeader, "default-src 'self'");
    assert.match(observation.finalUrl ?? "", /q=marker/);
  } finally {
    await adapter.close();
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
  }
});
