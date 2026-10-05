import { test } from "node:test";
import assert from "node:assert";
import { execSync } from "node:child_process";
import path from "node:path";
import { runSsrfScan } from "../cli/commands/ssrf/run.ts";
import { runBlindSsrfScan } from "../cli/commands/ssrf/blind.ts";

const scriptPath = path.resolve(import.meta.dirname, "../cli/commands/ssrf/index.ts");

test("run command parses options and outputs JSON array of payload targets", () => {
  const cmd = `node --experimental-strip-types "${scriptPath}" run "https://target.com/api/fetch" "url" --canary="https://poc-harness.com/c/TOKEN" --max=10`;
  const output = execSync(cmd, { encoding: "utf8" });
  // Split output by newline, discard routing message, and parse JSON
  const lines = output.trim().split("\n");
  const jsonStr = lines.find((l) => l.startsWith("[") || l.startsWith("{"));
  assert.ok(jsonStr, "Output must contain a JSON payload");
  const parsed = JSON.parse(jsonStr);
  assert.ok(Array.isArray(parsed));
  assert.ok(parsed.length <= 10);
  assert.ok(parsed.length > 0);
  // Ensure canary is present if generated
  const hasCanary = parsed.some((p: any) => p.category === "canary" || p.payload?.includes("poc-harness.com"));
  assert.ok(hasCanary);
});

test("blind command parses options and outputs JSON array of OOB callbacks", () => {
  const cmd = `node --experimental-strip-types "${scriptPath}" blind "https://target.com/webhook" "callback_url" --dns-only --watch --watch-timeout=50`;
  const output = execSync(cmd, { encoding: "utf8" });
  const lines = output.trim().split("\n");
  const jsonStr = lines.find((l) => l.startsWith("[") || l.startsWith("{"));
  assert.ok(jsonStr, "Output must contain a JSON payload");
  const parsed = JSON.parse(jsonStr);
  assert.ok(Array.isArray(parsed));
  assert.ok(parsed.length > 0);
  // Check dnsOnly payload structure - should not contain http:// if dns-only
  for (const item of parsed) {
    const payloadStr = typeof item === 'string' ? item : item.payload;
    assert.ok(!payloadStr.startsWith("http://"));
  }
});

test("run command filters cloud metadata when --no-cloud is passed", () => {
  const cmd = `node --experimental-strip-types "${scriptPath}" run "https://target.com/api/fetch" "url" --no-cloud`;
  const output = execSync(cmd, { encoding: "utf8" });
  const lines = output.trim().split("\n");
  const jsonStr = lines.find((l) => l.startsWith("[") || l.startsWith("{"));
  assert.ok(jsonStr, "Output must contain a JSON payload");
  const parsed = JSON.parse(jsonStr);
  assert.ok(Array.isArray(parsed));
  for (const item of parsed) {
    const category = typeof item === 'object' && item !== null ? item.category : '';
    const payloadStr = typeof item === 'object' && item !== null ? item.payload : String(item);
    assert.ok(category !== "cloud metadata");
    assert.ok(!payloadStr.includes("169.254.169.254"));
  }
});

test("programmatic validation for runSsrfScan inputs", () => {
  assert.throws(() => runSsrfScan("", "url"), TypeError);
  assert.throws(() => runSsrfScan("https://target.com", ""), TypeError);
  assert.throws(() => runSsrfScan("https://target.com", "url", { max: -5 }), RangeError);
  assert.throws(() => runSsrfScan("https://target.com", "url", { max: NaN }), RangeError);
});

test("programmatic validation for runBlindSsrfScan inputs", () => {
  assert.throws(() => runBlindSsrfScan("", "url"), TypeError);
  assert.throws(() => runBlindSsrfScan("https://target.com", ""), TypeError);
});

test("cli error behavior on invalid max boundary", () => {
  try {
    const cmd = `node --experimental-strip-types "${scriptPath}" run "https://target.com/api/fetch" "url" --max=-5`;
    execSync(cmd, { stdio: "pipe" });
    assert.fail("CLI should have exited with error code for negative max");
  } catch (error: any) {
    assert.ok(error.status === 1 || error.code === 1);
    const stderr = error.stderr.toString();
    assert.ok(stderr.includes("error: --max option requires a non-negative integer"));
  }
});

test("cli parses canary url with multiple equals signs correctly", () => {
  const cmd = `node --experimental-strip-types "${scriptPath}" run "https://target.com/api/fetch" "url" --canary="poc-harness.com=equal" --max=1`;
  const output = execSync(cmd, { encoding: "utf8" });
  const lines = output.trim().split("\n");
  const jsonStr = lines.find((l) => l.startsWith("[") || l.startsWith("{"));
  assert.ok(jsonStr, "Output must contain a JSON payload");
  const parsed = JSON.parse(jsonStr);
  const foundPayload = parsed.find((p: any) => p.category === "canary");
  assert.ok(foundPayload);
  assert.ok(foundPayload.payload.includes("poc-harness.com=equal"), "Should preserve equal sign in canary url");
});
