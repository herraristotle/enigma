import { test } from "node:test";
import assert from "node:assert";
import { SsrfRunner, type BrowserAdapter, type BrowserObservation, type RunOptions } from "../core/runner/index.ts";

function createMockBrowser(): BrowserAdapter & { calls: any[] } {
  const calls: any[] = [];
  return {
    calls,
    async injectHooks(_script: string): Promise<void> {},
    async navigate(target: string, parameter: string, payload: string, options?: RunOptions): Promise<BrowserObservation> {
      calls.push({ target, parameter, payload, options });
      return { statusCode: 200, blocked: false, reflected: false, executed: false, responseBody: "" };
    },
    async probe(_value: string) {
      return { blocked: false, reflected: false, successful: false };
    }
  };
}

test("SsrfRunner passes headers from plan to browser.navigate", async () => {
  const mockBrowser = createMockBrowser();
  const mockPlan = [
    {
      category: "header injection" as const,
      payload: "http://169.254.169.254",
      technique: "X-Forwarded-For",
      detail: "Proxy trust",
      headers: { "X-Forwarded-For": "127.0.0.1" }
    }
  ];

  const runner = new SsrfRunner(mockBrowser, {});
  await runner.run("http://test.com", "url", mockPlan);

  assert.strictEqual(mockBrowser.calls.length, 1);
  assert.strictEqual(mockBrowser.calls[0].target, "http://test.com");
  assert.strictEqual(mockBrowser.calls[0].parameter, "url");
  assert.strictEqual(mockBrowser.calls[0].payload, "http://169.254.169.254");
  assert.deepStrictEqual(mockBrowser.calls[0].options?.headers, { "X-Forwarded-For": "127.0.0.1" });
});

test("SsrfRunner passes multiple plan items with different headers", async () => {
  const mockBrowser = createMockBrowser();
  const mockPlan = [
    {
      category: "header injection" as const,
      payload: "http://169.254.169.254",
      technique: "X-Forwarded-For",
      detail: "Proxy trust",
      headers: { "X-Forwarded-For": "127.0.0.1" }
    },
    {
      category: "header injection" as const,
      payload: "http://169.254.169.254/latest/meta-data/",
      technique: "X-Forwarded-Host",
      detail: "Host override",
      headers: { "X-Forwarded-Host": "169.254.169.254" }
    }
  ];

  const runner = new SsrfRunner(mockBrowser, {});
  await runner.run("http://test.com", "url", mockPlan);

  assert.strictEqual(mockBrowser.calls.length, 2);
  assert.deepStrictEqual(mockBrowser.calls[0].options?.headers, { "X-Forwarded-For": "127.0.0.1" });
  assert.deepStrictEqual(mockBrowser.calls[1].options?.headers, { "X-Forwarded-Host": "169.254.169.254" });
});

test("SsrfRunner passes empty headers for plan items without headers", async () => {
  const mockBrowser = createMockBrowser();
  const mockPlan = [
    {
      category: "localhost admin" as const,
      payload: "http://localhost/admin",
      technique: "direct access",
      detail: "Localhost admin path"
    }
  ];

  const runner = new SsrfRunner(mockBrowser, {});
  await runner.run("http://test.com", "url", mockPlan);

  assert.strictEqual(mockBrowser.calls.length, 1);
  assert.deepStrictEqual(mockBrowser.calls[0].options?.headers, undefined);
});

test("SsrfRunner merges existing options with headers", async () => {
  const mockBrowser = createMockBrowser();
  const mockPlan = [
    {
      category: "header injection" as const,
      payload: "http://169.254.169.254",
      technique: "X-Forwarded-For",
      detail: "Proxy trust",
      headers: { "X-Forwarded-For": "127.0.0.1" }
    }
  ];

  const runner = new SsrfRunner(mockBrowser, { cookie: "session=abc" });
  await runner.run("http://test.com", "url", mockPlan);

  assert.strictEqual(mockBrowser.calls.length, 1);
  assert.strictEqual(mockBrowser.calls[0].options?.cookie, "session=abc");
  assert.deepStrictEqual(mockBrowser.calls[0].options?.headers, { "X-Forwarded-For": "127.0.0.1" });
});
