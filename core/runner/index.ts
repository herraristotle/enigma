import { MutationComposer } from "../engines/mutation/composer.ts";
import { detectContext, dualProbeSequence, type ContextName } from "../engines/mutation/context-techniques.ts";
import { getBaselineForContext } from "../engines/mutation/baselines.ts";
import { runBinarySearch, type TriggerProbeAdapter } from "../engines/trigger-finder.ts";
import { buildSinkHookScript } from "../engines/dom/sink-hooks.ts";
import { DecisionTreeLogger } from "../visualization/logger.ts";
import { LearningLoop, rotorToPhase, type LearningLoopSnapshot } from "../engines/mutation/learning-loop.ts";
import { buildMxssDetectionScript, analyzeMxss, type MxssVerdict } from "../engines/mutation/mxss.ts";
import { type StoredXssStage, type WorkflowRunResult, validateWorkflow, transformPayload } from "./workflow.ts";

export interface BrowserObservation {
  statusCode: number;
  blocked: boolean;
  reflected: boolean;
  executed: boolean;
  responseBody: string;
  sinkEvents?: unknown[];
  cspHeader?: string;
  finalUrl?: string;
}

export interface RunOptions {
  cookie?: string;
  source?: string;
  observeUrl?: string;
  formData?: Record<string, string>;
  injectHeader?: string;
  verbose?: boolean;
  headers?: Record<string, string>;
  /** When true, inject the mXSS detection script and check for parser-differential mutations. */
  enableMxssDetection?: boolean;
  /** Optional multi-step stored XSS workflow — if provided, replaces single inject/observe with stage-gated chain. */
  workflow?: StoredXssStage[];
}

export interface BrowserAdapter extends TriggerProbeAdapter {
  injectHooks(script: string): Promise<void>;
  navigate(target: string, parameter: string, payload: string, options?: RunOptions): Promise<BrowserObservation>;
  close?(): Promise<void>;
}

export interface RunResult {
  target: string;
  parameter: string;
  context: string;
  success: boolean;
  baseline: string;
  attempts: Array<{ payload: string; result: BrowserObservation }>;
  knowledge: Record<string, unknown>;
  log: ReturnType<DecisionTreeLogger["export"]>;
  /** Decision-map phase transcript (TEST → BLOCKED → LEARN → R2 → ... → TEST). */
  learningLoop: LearningLoopSnapshot;
}

export class EnigmaRunner {
  private readonly browser: BrowserAdapter;
  private readonly options: RunOptions;

  constructor(browser: BrowserAdapter, options: RunOptions = {}) {
    this.browser = browser;
    this.options = options;
  }

  async run(target: string, parameter: string): Promise<RunResult> {
    const logger = new DecisionTreeLogger();
    
    // Inject sink hooks + mXSS detection script (if enabled)
    await this.browser.injectHooks(buildSinkHookScript());
    logger.record("setup", "inject-hooks", "DOM sink monitoring enabled");
    if (this.options.enableMxssDetection) {
      await this.browser.injectHooks(buildMxssDetectionScript());
      logger.record("setup", "mxss-detection", "Mutation XSS parser-differential detection enabled");
    }

    if (this.options.observeUrl) {
      logger.record("setup", "stored-xss", `Injecting at ${target}, observing at ${this.options.observeUrl}`);
    }
    if (this.options.injectHeader) {
      logger.record("setup", "header-injection", `Injecting into header: ${this.options.injectHeader}`);
    }
    if (this.options.workflow) {
      const validationErrors = validateWorkflow(this.options.workflow);
      if (validationErrors.length > 0) {
        throw new Error(`Invalid workflow: ${validationErrors.join("; ")}`);
      }
      logger.record("setup", "workflow", `Multi-step stored XSS workflow: ${this.options.workflow.map(s => s.name).join(" → ")}`);
    }

    let context: ContextName = "html_content";
    const probes = dualProbeSequence();
    let lastObservation: BrowserObservation | null = null;

    for (const probe of probes) {
      if (this.options.verbose) console.log(`[R1] Sending probe: ${probe}`);
      const observation = await this.browser.navigate(target, parameter, probe, this.options);
      lastObservation = observation;
      logger.record("context", "probe", `${probe} => blocked=${observation.blocked} reflected=${observation.reflected}`);

      if (!observation.blocked) {
        context = detectContext(observation.responseBody, probe);
        logger.record("context", "detected", context);
        if (this.options.verbose) console.log(`[R1] Context detected: ${context}`);
        break;
      }

      if (observation.blocked && probe.includes("<")) {
        logger.record("context", "blocked-probe", "Angle bracket probe blocked, trying alphanumeric fallback");
        if (this.options.verbose) console.log(`[R1] Angle brackets blocked. Falling back to alphanumeric probe.`);
      }
    }

    if (lastObservation?.blocked && lastObservation.reflected) {
      context = detectContext(lastObservation.responseBody, probes[probes.length - 1]);
      logger.record("context", "fallback", `Used alphanumeric probe context: ${context}`);
    } else if (lastObservation?.blocked && !lastObservation.reflected) {
      logger.record("context", "undetermined", "All probes blocked and not reflected, defaulting to html_content");
      if (this.options.verbose) console.log(`[R1] Context unknown. Defaulting to html_content.`);
    }

    const composer = new MutationComposer(context);
    const learningLoop = new LearningLoop();
    const baseline = getBaselineForContext(context as never);
    const attempts: Array<{ payload: string; result: BrowserObservation }> = [];
    
    if (this.options.verbose) console.log(`[R2] Testing baseline payload: ${baseline.payload}`);
    const baselineResult = await this.browser.navigate(target, parameter, baseline.payload, this.options);
    attempts.push({ payload: baseline.payload, result: baselineResult });
    logger.record("baseline", "test", `${baseline.payload} => executed=${baselineResult.executed}`);
    learningLoop.record(baselineResult.executed ? "executed" : "blocked", baseline.payload, "R1 context baseline");
    
    // Pass raw CSP header to composer for directive-aware strategies
    if (baselineResult.cspHeader) {
      logger.record("baseline", "csp", baselineResult.cspHeader);
      composer.setCspDetected(true);
      composer.setCspRawHeader(baselineResult.cspHeader);
      if (this.options.verbose) console.log(`[CSP] Detected Content-Security-Policy: ${baselineResult.cspHeader}`);
    }

    // Angular version detection for angular_expression context
    if (context === "angular_expression") {
      const angularVersion = detectAngularVersion(baselineResult.responseBody);
      if (angularVersion) {
        composer.setAngularVersion(angularVersion);
        if (this.options.verbose) console.log(`[Angular] Detected version ${angularVersion} — selecting version-differential escapes`);
      }
    }

    if (baselineResult.executed) {
      if (this.options.verbose) console.log(`[!!] Baseline executed! XSS found.`);
      return this._buildResult(target, parameter, context, true, baseline.payload, attempts, composer, logger, learningLoop);
    }

    if (this.options.verbose) console.log(`[R2] Baseline blocked or failed. Running binary search...`);
    const binarySearch = await runBinarySearch(baseline.payload, this.browser);
    composer.absorbBinarySearch(binarySearch);
    logger.record("binary-search", "components", JSON.stringify(binarySearch));

    if (baselineResult.reflected) {
      const tag = baseline.payload.match(/^<([a-z0-9-]+)/i)?.[1] ?? "img";
      composer.absorbPartialSuccess("tag", tag);
      logger.record("foothold", "tag", "Reflected baseline created a foothold");
      if (this.options.verbose) console.log(`[R2] Reflected tag '${tag}' recorded as foothold.`);
    }

    // Execute multi-step stored XSS workflow if provided
    if (this.options.workflow) {
      const workflowResult = await this.executeWorkflow(target, parameter, this.options.workflow, composer, logger, learningLoop);
      if (workflowResult.firedAtStageIndex !== undefined) {
        // XSS fired at a workflow stage — merge attempts and return success
        const allAttempts = [...attempts, ...workflowResult.stages.map(s =>
          ({ payload: s.payload, result: { executed: s.executed, reflected: s.reflected, blocked: s.blocked } as BrowserObservation })
        )];
        if (this.options.verbose) console.log(`[!!] Workflow stage ${workflowResult.firedAtStageIndex} (${this.options.workflow[workflowResult.firedAtStageIndex].name}) executed! XSS found.`);
        return this._buildResult(target, parameter, context, true, baseline.payload, allAttempts, composer, logger, learningLoop);
      }
    }

    let candidateBudget = 50; // Increased budget
    while (candidateBudget > 0) {
      const batch = composer.nextCandidates().slice(0, Math.min(8, candidateBudget));
      if (batch.length === 0) {
        if (this.options.verbose) console.log(`[Enigma] Exhausted all bypass cascades.`);
        break;
      }
      
      for (const candidate of batch) {
        candidateBudget -= 1;
        if (this.options.verbose) console.log(`[R4] Testing candidate (${candidate.rationale}): ${candidate.payload}`);
        
        const result = await this.browser.navigate(target, parameter, candidate.payload, this.options);
        attempts.push({ payload: candidate.payload, result });
        logger.record(candidate.rotor, "candidate", `${candidate.rationale} => executed=${result.executed} blocked=${result.blocked}`);
        const loopOutcome = result.executed ? "executed" : result.blocked ? "blocked" : "reflected";
        learningLoop.record(loopOutcome, candidate.payload, `${candidate.rationale} [rotor: ${candidate.rotor}]`);

        if (result.executed) {
          if (this.options.verbose) console.log(`[!!] Payload executed! ${candidate.payload}`);
          return this._buildResult(target, parameter, context, true, baseline.payload, attempts, composer, logger, learningLoop);
        }

        // mXSS detection on reflected-but-not-executed payloads
        if (this.options.enableMxssDetection && result.reflected && !result.blocked && !result.executed) {
          const mxssCheck = await this.browser.evaluate(buildMxssDetectionScript() + `\n__enigmaMxssDetect(${JSON.stringify(candidate.payload)});`);
          const verdict = analyzeMxss(mxssCheck);
          if (verdict.verdict === "mxss_mutation") {
            logger.record("mxss", "detected", `Mutation XSS detected: ${verdict.matchedVector?.name} → ${verdict.exposesSink}`);
            if (this.options.verbose) console.log(`[mXSS] Parser-differential mutation detected: ${verdict.matchedVector?.name}`);
          }
        }

        if (result.reflected && !result.blocked) {
          const tagMatch = candidate.payload.match(/^<([a-z0-9-]+)/i);
          const eventMatch = candidate.payload.match(/\s(on[a-z]+)=/i);
          if (tagMatch) {
            composer.absorbPartialSuccess("tag", tagMatch[1]);
            logger.record("foothold", "tag", tagMatch[1]);
          }
          if (eventMatch) {
            composer.absorbPartialSuccess("event", eventMatch[1]);
            logger.record("foothold", "event", eventMatch[1]);
          }
        }

        if (result.blocked) {
          const search = await runBinarySearch(candidate.payload, this.browser);
          composer.absorbBinarySearch(search);
          logger.record("binary-search", "blocked-candidate", JSON.stringify(search));
        }
      }
    }

    return this._buildResult(target, parameter, context, false, baseline.payload, attempts, composer, logger, learningLoop);
  }

  /**
   * Execute a multi-step stored XSS workflow. Each stage is a separate
   * inject→observe cycle with its own context detection, mutation cascade,
   * and composer knowledge inheritance.
   */
  private async executeWorkflow(
    target: string,
    parameter: string,
    workflow: StoredXssStage[],
    composer: MutationComposer,
    logger: DecisionTreeLogger,
    learningLoop: LearningLoop
  ): Promise<WorkflowRunResult> {
    const stageResults: WorkflowRunResult["stages"] = [];
    const skippedStages: number[] = [];

    for (let i = 0; i < workflow.length; i++) {
      const stage = workflow[i];
      logger.record("workflow", `stage-${stage.name}`, `Executing workflow stage ${i}: ${stage.name}`);

      // Build run options for this stage
      const stageOptions = {
        ...this.options,
        cookie: stage.cookie ?? this.options.cookie,
        observeUrl: stage.observeUrl,
        formData: stage.formData,
        source: this.options.source
      };

      // For workflow stages after the first, the injection URL is the stage's injectUrl
      const injectUrl = stage.injectUrl;
      const observeUrl = stage.observeUrl;

      // Run context detection for this stage
      let stageContext: ContextName = "html_content";
      const probes = dualProbeSequence();
      let lastObs: BrowserObservation | null = null;

      for (const probe of probes) {
        const observation = await this.browser.navigate(injectUrl, parameter, probe, stageOptions);
        lastObs = observation;
        if (!observation.blocked) {
          stageContext = detectContext(observation.responseBody, probe);
          break;
        }
      }

      // Create stage-specific composer with FULL parent knowledge transfer
      // (blockers, footholds, tested payloads, binary-search learnings,
      // CSP/Angular state) — absorbState covers everything exportState holds.
      const stageComposer = new MutationComposer(stageContext);
      stageComposer.absorbState(composer.state);

      // Test baseline
      const baseline = getBaselineForContext(stageContext as never);
      const baselineResult = await this.browser.navigate(injectUrl, parameter, baseline.payload, stageOptions);
      logger.record("workflow", `${stage.name}-baseline`, `${baseline.payload} => executed=${baselineResult.executed}`);
      
      if (baselineResult.executed) {
        learningLoop.record("executed", baseline.payload, `workflow:${stage.name} baseline`);
        composer.absorbState(stageComposer.state);
        return {
          firedAtStageIndex: i,
          stages: [...stageResults, {
            name: stage.name,
            executed: true,
            contextDetected: stageContext,
            reflected: baselineResult.reflected,
            blocked: baselineResult.blocked,
            payload: baseline.payload
          }],
          skippedStages: workflow.slice(i + 1).map((_, idx) => i + 1 + idx)
        };
      }
      if (baselineResult.blocked) learningLoop.record("blocked", baseline.payload, `workflow:${stage.name} baseline`);
      else if (baselineResult.reflected) learningLoop.record("reflected", baseline.payload, `workflow:${stage.name} baseline`);

      // Binary search and mutation cascade (simplified per stage)
      const binarySearch = await runBinarySearch(baseline.payload, this.browser);
      stageComposer.absorbBinarySearch(binarySearch);

      // Test mutation candidates for this stage
      let stageBudget = 10; // Reduced budget per stage
      let stageExecuted = false;
      let stagePayload = baseline.payload;
      let stageReflected = baselineResult.reflected;
      let stageBlocked = baselineResult.blocked;

      while (stageBudget > 0 && !stageExecuted) {
        const candidates = stageComposer.nextCandidates().slice(0, 4);
        if (candidates.length === 0) break;

        for (const candidate of candidates) {
          stageBudget--;
          const transformedPayload = transformPayload(candidate.payload, stage.payloadTransform ?? "identity");
          const result = await this.browser.navigate(injectUrl, parameter, transformedPayload, stageOptions);
          
          if (result.executed) {
            stageExecuted = true;
            stagePayload = transformedPayload;
            stageReflected = result.reflected;
            stageBlocked = result.blocked;
            learningLoop.record("executed", transformedPayload, `workflow:${stage.name} candidate`);
            break;
          }
        }
      }

      stageResults.push({
        name: stage.name,
        executed: stageExecuted,
        contextDetected: stageContext,
        reflected: stageReflected,
        blocked: stageBlocked,
        payload: stagePayload
      });

      // Feedback edge: stage learnings (blockers inferred by binary search,
      // tested payloads, footholds) merge back into the parent composer so
      // the NEXT stage's candidate ordering is informed by this stage.
      composer.absorbState(stageComposer.state);

      if (stageExecuted) {
        return {
          firedAtStageIndex: i,
          stages: stageResults,
          skippedStages: workflow.slice(i + 1).map((_, idx) => i + 1 + idx)
        };
      }
    }

    return {
      stages: stageResults,
      skippedStages: []
    };
  }

  private _buildResult(target: string, parameter: string, context: ContextName, success: boolean, baseline: string, attempts: any[], composer: MutationComposer, logger: DecisionTreeLogger, learningLoop: LearningLoop): RunResult {
    return {
      target,
      parameter,
      context,
      success,
      baseline,
      attempts,
      knowledge: composer.exportState(),
      log: logger.export(),
      learningLoop: learningLoop.snapshot()
    };
  }
}

export class PuppeteerBrowserAdapter implements BrowserAdapter {
  private browser: any;
  private page: any;
  private lastTarget = "https://example.com";
  private lastParameter = "q";
  private lastOptions: RunOptions = {};

  async init(headless = true): Promise<void> {
    const puppeteer = await import("puppeteer");
    this.browser = await puppeteer.launch({
      headless,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-crash-reporter",
        "--disable-breakpad"
      ]
    });
    this.page = await this.browser.newPage();
  }

  async injectHooks(script: string): Promise<void> {
    if (!this.page) throw new Error("PuppeteerBrowserAdapter.init() must run before injectHooks()");
    await this.page.evaluateOnNewDocument(script);
  }

  async navigate(target: string, parameter: string, payload: string, options: RunOptions = {}): Promise<BrowserObservation> {
    if (!this.page) throw new Error("PuppeteerBrowserAdapter.init() must run before navigate()");

    this.lastTarget = target;
    this.lastParameter = parameter;
    this.lastOptions = options;

    if (options.cookie) {
      const urlObj = new URL(target);
      const cookies = options.cookie.split(";").map(c => {
        const [name, value] = c.split("=").map(s => s.trim());
        return { name, value, domain: urlObj.hostname };
      });
      await this.page.setCookie(...cookies);
    }

    let executed = false;
    let cdpNavigated = false;
    
    this.page.removeAllListeners("dialog");
    this.page.removeAllListeners("request");
    
    this.page.on("dialog", async (dialog: any) => {
      executed = true;
      await dialog.dismiss();
    });

    await this.page.setRequestInterception(true);
    this.page.on("request", (req: any) => {
      if (req.url().startsWith("javascript:")) {
        cdpNavigated = true;
        executed = true;
        req.abort().catch(() => {});
      } else {
        // Handle Header Injection
        if (options.injectHeader && parameter === options.injectHeader) {
          const headers = req.headers();
          headers[options.injectHeader] = payload;
          req.continue({ headers }).catch(() => {});
        } else {
          req.continue().catch(() => {});
        }
      }
    });

    let response: any = null;
    let responseBody = "";
    const url = new URL(target);

    // Context Injection Strategy
    if (options.source === "hash") {
      url.hash = payload;
    } else if (options.source === "path") {
      url.pathname = `${url.pathname.replace(/\/+$/, "")}/${encodeURIComponent(payload)}`;
    } else if (parameter && !options.injectHeader) {
      url.searchParams.set(parameter, payload);
    }

    try {
      if (options.formData && options.observeUrl) {
        const injectData = new URLSearchParams(options.formData);
        injectData.set(parameter, payload);
        
        await this.page.goto(url.toString(), { waitUntil: "domcontentloaded" });
        await this.page.evaluate((action: string, data: string) => {
          return fetch(action, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: data
          });
        }, url.toString(), injectData.toString());

        response = await this.page.goto(options.observeUrl, { waitUntil: "networkidle2" });
      } else {
        response = await this.page.goto(url.toString(), { waitUntil: "domcontentloaded" });
      }
      
      // Allow async auto-fire executors to run (e.g. timeout, intervals, animations)
      await new Promise(r => setTimeout(r, 100));
      responseBody = await this.page.content();
    } catch (e: any) {
      if (e.message.includes("net::ERR_ABORTED") && cdpNavigated) {
        executed = true; // javascript: navigation aborted intentionally
      }
    }

    const xssFlag = await this.page.evaluate(() => {
      return (window as any).__enigmaGetXssConfirmation?.();
    });
    
    if (xssFlag) {
      executed = true;
    }

    const sinkEvents = await this.page.evaluate(() => {
      return (window as any).__enigmaGetSinkEvents?.() ?? [];
    });
    
    const consoleSignals = await this.page.evaluate(() => {
      return Array.from(document.querySelectorAll("[popover],[autofocus],svg,details")).map((node) => (node as Element).tagName.toLowerCase());
    });

    const reflected = responseBody.includes(payload) || responseBody.includes(encodeURIComponent(payload));
    const cspHeader = response?.headers()?.["content-security-policy"] ?? "";
    const statusCode = response?.status() ?? 0;
    
    const blocked = statusCode === 403
      || statusCode === 406
      || statusCode === 429
      || /access denied|request blocked|cloudflare|akamai|imperva|modsecurity|waf/i.test(responseBody);
      
    const executedBySink = Array.isArray(sinkEvents) && sinkEvents.length > 0;

    return {
      statusCode,
      blocked,
      reflected,
      executed: executed || executedBySink,
      responseBody,
      sinkEvents: [...(Array.isArray(sinkEvents) ? sinkEvents : []), ...consoleSignals],
      cspHeader,
      finalUrl: this.page.url()
    };
  }

  async probe(value: string): Promise<{ blocked: boolean; reflected: boolean; successful: boolean }> {
    const observation = await this.navigate(this.lastTarget, this.lastParameter, value, this.lastOptions);
    return {
      blocked: observation.blocked,
      reflected: observation.reflected,
      successful: observation.executed
    };
  }

  async close(): Promise<void> {
    await this.browser?.close();
  }
}

export interface SsrfPlanItem {
  category: string;
  payload: string;
  technique?: string;
  detail?: string;
  headers?: Record<string, string>;
}

export class SsrfRunner {
  private readonly browser: BrowserAdapter;
  private readonly options: RunOptions;

  constructor(browser: BrowserAdapter, options: RunOptions = {}) {
    this.browser = browser;
    this.options = options;
  }

  async run(target: string, parameter: string, plan: SsrfPlanItem[]): Promise<void> {
    for (const item of plan) {
      await this.browser.navigate(target, parameter, item.payload, {
        ...this.options,
        headers: item.headers
      });
    }
  }
}
