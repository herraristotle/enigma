import {
  ContentMatcher,
  NotificationManager,
  SlackNotification,
  TerminalNotification,
  TimingAnalyzer,
  SizeAnalyzer,
  type ContentMatch,
  type ScanResult
} from "./canary.ts";
import type { TraceSink } from "../../trace.ts";
import {
  advanceScanState,
  assessImpact,
  createScanState,
  type SsrfPayload
} from "./decision-trees.ts";

export interface SsrfExecutionOptions {
  /** Per-request timeout in milliseconds (default 5000). */
  timeoutMs?: number;
  /** State-machine attempt budget (default: plan length). */
  maxAttempts?: number;
  /** When set, adds a Slack channel alongside the default terminal channel. */
  slackWebhook?: string;
  /** Inject a preconfigured manager (tests); overrides slackWebhook default. */
  notifications?: NotificationManager;
  verbose?: boolean;
  /** NDJSON trace sink — emits one probe record per request. */
  trace?: TraceSink;
}

export interface SsrfExecutionOutcome {
  results: ScanResult[];
  phase: string;
  attempts: number;
  confirmed: number;
  /** Blind fallback (OOB unavailable): statistical timing + size side channels. */
  statistical?: {
    timing: ReturnType<typeof TimingAnalyzer.analyze>;
    sizes: ReturnType<typeof SizeAnalyzer.analyzeGroups>;
  };
}

/** Payload destination host (measurement target for timeout patterns). */
function hostOf(payload: string): string {
  try {
    return new URL(payload).hostname;
  } catch {
    return payload;
  }
}

function isInternalHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h === "::1" || h.endsWith(".local")) return true;
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 127 || a === 10 || (a === 192 && b === 168) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
}

/** Statuses that indicate a defensive block rather than absence of signal. */
const BLOCKED_STATUSES = new Set([401, 403, 406, 429, 503]);

function buildDefaultNotifications(slackWebhook?: string): NotificationManager {
  const manager = new NotificationManager();
  manager.addChannel(new TerminalNotification());
  if (slackWebhook) manager.addChannel(new SlackNotification(slackWebhook));
  return manager;
}

interface Classification {
  result: "confirmed" | "blocked" | "no_signal";
  matches: ContentMatch[];
  level: "confirmed" | "suspected" | "none";
}

function classifyResponse(status: number, body: string): Classification {
  const matches = ContentMatcher.analyze(body);
  const level = ContentMatcher.getConfirmationLevel(matches);
  if (level === "confirmed" || level === "suspected") {
    return { result: "confirmed", matches, level };
  }
  if (BLOCKED_STATUSES.has(status)) {
    return { result: "blocked", matches, level };
  }
  return { result: "no_signal", matches, level };
}

/**
 * Executes an SSRF payload plan against a target parameter.
 *
 * Each plan item's payload is injected as a query-parameter value on
 * `targetUrl`; plan-supplied request headers are attached verbatim.
 * Responses are classified (confirmed / blocked / no_signal) via content
 * fingerprints, fed through the 4-phase scan state machine, and confirmed
 * hits get CVSS impact assessment + notification delivery.
 */
export async function executeSsrfPlan(
  targetUrl: string,
  parameter: string,
  plan: SsrfPayload[],
  options: SsrfExecutionOptions = {}
): Promise<SsrfExecutionOutcome> {
  if (!targetUrl) throw new TypeError("targetUrl is required");
  if (!parameter) throw new TypeError("parameter is required");

  const timeoutMs = options.timeoutMs ?? 5000;
  options.trace?.setStage("ssrf");
  const notifications = options.notifications ?? buildDefaultNotifications(options.slackWebhook);
  let state = createScanState(options.maxAttempts ?? plan.length);
  const results: ScanResult[] = [];
  const measurements: Array<{ target: string; durationMs: number }> = [];
  const internalSizes: number[] = [];
  const externalSizes: number[] = [];
  let confirmed = 0;

  for (const item of plan) {
    const started = Date.now();
    let status: ScanResult["status"];
    let matches: ContentMatch[] = [];
    let level: Classification["level"] = "none";
    let httpStatus = 0;
    let bodyLen = 0;

    try {
      const url = new URL(targetUrl);
      url.searchParams.set(parameter, item.payload);
      const response = await fetch(url.toString(), {
        method: "GET",
        headers: item.headers,
        redirect: "follow",
        signal: AbortSignal.timeout(timeoutMs)
      });
      httpStatus = response.status;
      const body = await response.text();
      bodyLen = body.length;
      const classified = classifyResponse(httpStatus, body);
      status = classified.result;
      matches = classified.matches;
      level = classified.level;
      if (options.verbose) {
        console.error(
          `[ssrf] ${status} http=${httpStatus} category=${item.category} payload=${item.payload.slice(0, 80)}`
        );
      }
    } catch (err) {
      // Network error or timeout — record as error, treat as no_signal for the state machine.
      status = "error";
      if (options.verbose) {
        console.error(`[ssrf] error payload=${item.payload.slice(0, 80)} :: ${String(err)}`);
      }
    }

    const durationMs = Date.now() - started;
    measurements.push({ target: hostOf(item.payload), durationMs });
    if (httpStatus > 0) {
      if (isInternalHost(hostOf(item.payload))) internalSizes.push(bodyLen);
      else externalSizes.push(bodyLen);
    }
    options.trace?.probe({
      method: "GET",
      url: targetUrl,
      status: status === "error" ? 0 : httpStatus,
      latencyMs: durationMs,
      reason: `${item.category}:${status}`
    });

    const scanResult: ScanResult = {
      target: targetUrl,
      payload: item.payload,
      technique: item.technique ?? "",
      category: item.category,
      status,
      timestamp: Date.now(),
      durationMs,
      contentMatches: matches.length > 0 ? matches : undefined,
      confirmationLevel: status === "error" ? undefined : level
    };

    if (status === "confirmed") {
      confirmed += 1;
      const impact = assessImpact(
        item.category,
        item.technique ?? "",
        level === "confirmed",
        matches
      );
      scanResult.cvss = impact.cvss;
      await notifications.notify(scanResult);
      results.push(scanResult);
      const advanced = advanceScanState(state, "confirmed");
      state = advanced.state;
      // A hard (high-confidence) confirmation ends the scan; suspected
      // confirmations keep the loop going so the machine can cross-check.
      if (level === "confirmed" || !advanced.shouldContinue) break;
      continue;
    }

    results.push(scanResult);

    const machineResult: "confirmed" | "blocked" | "no_signal" =
      status === "blocked" ? "blocked" : "no_signal";
    const advanced = advanceScanState(state, machineResult);
    state = advanced.state;
    if (!advanced.shouldContinue) break;
  }

  const outcome: SsrfExecutionOutcome = {
    results,
    phase: state.phase,
    attempts: state.attempts,
    confirmed
  };
  // Blind fallback: no direct confirmation → statistical timing + size
  // side channels (competitor parity: "statistical timing analysis").
  if (confirmed === 0 && measurements.length >= 2) {
    outcome.statistical = {
      timing: TimingAnalyzer.analyze(measurements, { baselineMs: timeoutMs }),
      sizes: SizeAnalyzer.analyzeGroups(internalSizes, externalSizes)
    };
  }
  return outcome;
}
