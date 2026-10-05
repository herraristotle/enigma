import { CanaryRegistry, NotificationManager, SlackNotification, TerminalNotification, type ScanResult } from "../../../core/engines/ssrf/canary.ts";
import { assessImpact } from "../../../core/engines/ssrf/decision-trees.ts";

export interface BlindScanOptions {
  dnsOnly?: boolean;
  watch?: boolean;
  canaryUrl?: string;
}

export interface WatchOptions {
  targetUrl?: string;
  parameter?: string;
  /** Inject a preconfigured manager (tests); overrides slackWebhook default. */
  notifications?: NotificationManager;
  /** When set, adds a Slack channel alongside the default terminal channel. */
  slackWebhook?: string;
  timeoutMs?: number;
  intervalMs?: number;
  /** Injected poller for tests — returns raw poll body, or null when quiet. */
  pollFn?: (pollUrl: string) => Promise<string | null>;
}

/** Terminal + optional Slack channels — same default set the executor uses. */
export function buildBlindNotifications(slackWebhook?: string): NotificationManager {
  const manager = new NotificationManager();
  manager.addChannel(new TerminalNotification());
  if (slackWebhook) manager.addChannel(new SlackNotification(slackWebhook));
  return manager;
}

export function runBlindSsrfScan(
  targetUrl: string,
  parameter: string,
  options: BlindScanOptions = {}
): string[] {
  if (!targetUrl) {
    throw new TypeError("targetUrl is required");
  }
  if (!parameter) {
    throw new TypeError("parameter is required");
  }
  const canaryUrl = options.canaryUrl || "http://localhost:8080/c/TOKEN";
  let domain = canaryUrl;
  try {
    if (domain.includes("://")) {
      const url = new URL(domain);
      domain = url.hostname;
    }
  } catch {}

  const registry = new CanaryRegistry();
  const token = registry.register({
    target: targetUrl,
    parameter,
    payload: "PLACEHOLDER",
    technique: "blind"
  }, domain);

  const record = registry.get(token);
  if (!record) {
    return [];
  }

  if (options.dnsOnly) {
    return [record.callbacks.dnsOnly];
  }

  return [
    record.callbacks.directHttp,
    record.callbacks.dnsOnly,
    record.callbacks.pathIdentified,
    record.callbacks.redirectChain
  ];
}

async function main() {
  const targetUrl = process.argv[2];
  const parameter = process.argv[3];
  if (!targetUrl || !parameter) {
    console.error("usage: enigma-ssrf blind <targetUrl> <parameter> [options]");
    process.exitCode = 1;
    return;
  }

  let dnsOnly = false;
  let watch = false;
  let canaryUrl: string | undefined;
  let slackWebhook: string | undefined;
  let watchTimeoutMs = 60_000;

  for (const arg of process.argv.slice(4)) {
    if (arg === "--dns-only") {
      dnsOnly = true;
    } else if (arg === "--watch") {
      watch = true;
    } else if (arg.startsWith("--canary=")) {
      canaryUrl = arg.slice(arg.indexOf("=") + 1);
    } else if (arg.startsWith("--slack-webhook=")) {
      slackWebhook = arg.slice(arg.indexOf("=") + 1);
    } else if (arg.startsWith("--watch-timeout=")) {
      const parsed = Number.parseInt(arg.slice(arg.indexOf("=") + 1), 10);
      if (Number.isFinite(parsed) && parsed >= 0) watchTimeoutMs = parsed;
    }
  }

  const result = runBlindSsrfScan(targetUrl, parameter, { dnsOnly, watch, canaryUrl });
  console.log(JSON.stringify(result));

  if (watch) {
    await watchForCallbacks(canaryUrl || "http://localhost:8080/c/TOKEN", {
      targetUrl,
      parameter,
      slackWebhook,
      timeoutMs: watchTimeoutMs
    });
  }
}

/**
 * Continuous OOB watch: delayed SSRF (async webhooks, PDF queues) may fire
 * minutes after submission. Polls the canary's HTTP status endpoint; on
 * callback activity, notifies every channel (terminal + optional Slack)
 * with a confirmed ScanResult and returns it so callers can exit.
 * Returns null on timeout.
 */
export async function watchForCallbacks(canaryUrl: string, options: WatchOptions = {}): Promise<ScanResult | null> {
  const notifications = options.notifications ?? buildBlindNotifications(options.slackWebhook);
  const timeoutMs = options.timeoutMs ?? 60_000;
  const intervalMs = options.intervalMs ?? 5_000;
  const pollFn = options.pollFn ?? (async (pollUrl: string): Promise<string | null> => {
    try {
      const res = await fetch(pollUrl, { method: "GET" });
      if (res.ok) return await res.text();
    } catch {
      // Canary poll endpoint optional — keep watching.
    }
    return null;
  });

  // Poll endpoint: canary URLs of the form .../c/<token> expose .../poll.
  const pollUrl = canaryUrl.includes("/c/")
    ? canaryUrl.replace(/\/c\/[^/]+\/?$/, "/poll")
    : canaryUrl.replace(/\/+$/, "") + "/poll";

  const started = Date.now();
  console.error(`[watch] listening for delayed callbacks (timeout=${timeoutMs}ms)`);
  for (;;) {
    const remaining = timeoutMs - (Date.now() - started);
    if (remaining <= 0) break;
    await new Promise((r) => setTimeout(r, Math.min(intervalMs, remaining)));
    const body = await pollFn(pollUrl);
    if (body && body !== "[]" && body !== "{}") {
      console.error(`[watch] callback activity detected: ${body.slice(0, 200)}`);
      const impact = assessImpact("internal service", "blind", true);
      const scanResult: ScanResult = {
        target: options.targetUrl ?? canaryUrl,
        payload: body.slice(0, 500),
        technique: "blind-oob-callback",
        category: "internal service",
        status: "confirmed",
        timestamp: Date.now(),
        confirmationLevel: "confirmed",
        cvss: impact.cvss
      };
      await notifications.notify(scanResult);
      return scanResult;
    }
  }
  console.error("[watch] done");
  return null;
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("blind.ts")) {
  void main();
}
