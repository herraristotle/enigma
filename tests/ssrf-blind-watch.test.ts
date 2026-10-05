import { test } from "node:test";
import assert from "node:assert";
import { watchForCallbacks, buildBlindNotifications } from "../cli/commands/ssrf/blind.ts";
import { NotificationManager, type ScanResult } from "../core/engines/ssrf/canary.ts";

function capturingManager(received: ScanResult[]): NotificationManager {
  const manager = new NotificationManager();
  manager.addChannel({ async send(r: ScanResult) { received.push(r); } });
  return manager;
}

test("watchForCallbacks — OOB callback triggers confirmed notification with CVSS", async () => {
  const received: ScanResult[] = [];
  let polls = 0;
  let seenPollUrl = "";

  const result = await watchForCallbacks("http://canary.test/c/abc123", {
    targetUrl: "https://victim.test/fetch",
    parameter: "url",
    notifications: capturingManager(received),
    timeoutMs: 2000,
    intervalMs: 10,
    pollFn: async (pollUrl) => {
      seenPollUrl = pollUrl;
      polls++;
      return polls < 2 ? "[]" : '[{"token":"abc123","source":"http"}]';
    }
  });

  assert.ok(result, "watch should return a confirmed result");
  assert.strictEqual(result.status, "confirmed");
  assert.strictEqual(result.confirmationLevel, "confirmed");
  assert.strictEqual(result.target, "https://victim.test/fetch");
  assert.ok(result.cvss && result.cvss.base >= 7.5, `expected CVSS >= 7.5, got ${JSON.stringify(result.cvss)}`);
  assert.strictEqual(received.length, 1, "notification channel should fire exactly once");
  assert.strictEqual(received[0].technique, "blind-oob-callback");
  // Poll URL derived once from canary base — no duplicated /poll suffix.
  assert.strictEqual(seenPollUrl, "http://canary.test/poll");
});

test("watchForCallbacks — timeout with quiet canary returns null, no notification", async () => {
  const received: ScanResult[] = [];

  const result = await watchForCallbacks("http://canary.test/c/tok", {
    notifications: capturingManager(received),
    timeoutMs: 45,
    intervalMs: 15,
    pollFn: async () => "[]"
  });

  assert.strictEqual(result, null);
  assert.strictEqual(received.length, 0);
});

test("buildBlindNotifications — terminal default, Slack added when webhook set", () => {
  const bare = buildBlindNotifications() as unknown as { channels: unknown[] };
  assert.strictEqual(bare.channels.length, 1);

  const withSlack = buildBlindNotifications("https://hooks.slack.test/x") as unknown as { channels: unknown[] };
  assert.strictEqual(withSlack.channels.length, 2);
});
