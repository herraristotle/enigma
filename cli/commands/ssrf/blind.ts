import { CanaryRegistry } from "../../../core/engines/ssrf/canary.ts";

export interface BlindScanOptions {
  dnsOnly?: boolean;
  watch?: boolean;
  canaryUrl?: string;
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

  for (const arg of process.argv.slice(4)) {
    if (arg === "--dns-only") {
      dnsOnly = true;
    } else if (arg === "--watch") {
      watch = true;
    } else if (arg.startsWith("--canary=")) {
      canaryUrl = arg.slice(arg.indexOf("=") + 1);
    }
  }

  const result = runBlindSsrfScan(targetUrl, parameter, { dnsOnly, watch, canaryUrl });
  console.log(JSON.stringify(result));

  if (watch) {
    // Continuous OOB watch: delayed SSRF (async webhooks, PDF queues) may fire
    // minutes after submission. Poll the canary domain's HTTP status endpoint
    // when operators supply a pollable canary base; otherwise keep process alive
    // so an external harness can correlate tokens.
    const timeoutMs = 60_000;
    const intervalMs = 5_000;
    const started = Date.now();
    console.error(`[watch] listening for delayed callbacks (timeout=${timeoutMs}ms)`);
    while (Date.now() - started < timeoutMs) {
      await new Promise((r) => setTimeout(r, intervalMs));
      if (canaryUrl) {
        try {
          const pollUrl = canaryUrl.replace(/\/c\/[^/]+\/?$/, "/poll").replace(/\/$/, "") + "/poll";
          const res = await fetch(pollUrl, { method: "GET" });
          if (res.ok) {
            const body = await res.text();
            if (body && body !== "[]" && body !== "{}") {
              console.error(`[watch] callback activity detected: ${body.slice(0, 200)}`);
              break;
            }
          }
        } catch {
          // Canary poll endpoint optional — continue watching
        }
      }
    }
    console.error("[watch] done");
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("blind.ts")) {
  void main();
}
