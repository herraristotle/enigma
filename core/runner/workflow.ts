/**
 * Multi-step stored XSS — workflow state machine.
 *
 * The competitor blog flags single inject→observe as incomplete:
 *   "Multi-step stored XSS — current stored XSS support handles inject-
 *    then-observe, but complex flows (inject in profile, trigger in admin
 *    panel, execute in email notification) require workflow modeling."
 *
 * This module defines a `StoredXssWorkflow` — a DAG of (target, parameter,
 * injection-context-cookie) stages plus the transport between them (POST,
 * form submit, internal redirect). Each stage corresponds to a render/delivery
 * channel and gets its OWN R1 context detection → R2 binary search → R3-5
 * mutation cascade, run against the SAME composer knowledge state so a foothold
 * discovered at one stage (e.g. admin panel reflects the param with custom
 * filtering) influences the next stage's candidate ordering (e.g. email
 * notification renders the param raw and inherits zero filtering).
 *
 * Per-stage cookie switching models the role transition (victim → admin →
 * automated mail renderer) without an external auth-router component. The
 * runner drives each stage sequentially; between stages it persists the
 * composer state into the `EnigmaSession` knowledge dict so an agent-mode
 * operator can inspect footholds captured at each stage.
 *
 * The workflow terminates on the first stage that produces an `executed`
 * test result; downstream stages are skipped in that case because XSS
 * already fires in-context and the engine has no reason to escalate the
 * chain further.
 */

export interface StoredXssStage {
  /** Human-readable label ("profile", "admin-panel", "email-notification"). */
  name: string;
  /** Target URL where the parameter is INJECTED (a form action or JSON body post). */
  injectUrl: string;
  /** Target URL where the parameter RENDERED in this stage's context. */
  observeUrl: string;
  /** Authentication cookie for this stage's role (different from victim cookie). */
  cookie?: string;
  /** Optional transformation applied to payload before posting (e.g. URL-encode
   *  for JSON body vs raw for form). Default identity. */
  payloadTransform?: "identity" | "url-encode" | "json-string-escape";
  /** Whether to bypass R1 context detection and trust the workflow's stated context. */
  expectedContext?: string;
  /** Optional form fields to submit alongside the parameter (profile body). */
  formData?: Record<string, string>;
}

export interface WorkflowRunResult {
  /** Stage that fired execution; absent if no stage fired. */
  firedAtStageIndex?: number;
  /** Per-stage observation primitives so the caller can record into the session. */
  stages: Array<{
    name: string;
    executed: boolean;
    contextDetected?: string;
    reflected: boolean;
    blocked: boolean;
    payload: string;
  }>;
  /** Workflows that did not fire and were skipped due to upstream success. */
  skippedStages: number[];
}

/**
 * Validate the stage DAG before execution. Catches common errors:
 *   - empty workflow
 *   - duplicate stage names
 *   - missing injectUrl or observeUrl on any stage
 *   - cycles (impossible because stages are sequential, but kept as sanity)
 */
export function validateWorkflow(stages: StoredXssStage[]): string[] {
  const errors: string[] = [];
  if (stages.length === 0) errors.push("workflow must contain at least one stage");
  const names = new Set<string>();
  for (const s of stages) {
    if (names.has(s.name)) errors.push(`duplicate stage name: ${s.name}`);
    names.add(s.name);
    if (!s.injectUrl) errors.push(`stage ${s.name} has no injectUrl`);
    if (!s.observeUrl) errors.push(`stage ${s.name} has no observeUrl`);
  }
  return errors;
}

/**
 * Transform a payload according to a stage's encoding requirement.
 * Used by the runner before posting to injectUrl when the payload survives a
 * form-data POST that escapes differently per request type.
 */
export function transformPayload(payload: string, transform: Required<StoredXssStage>["payloadTransform"] = "identity"): string {
  switch (transform) {
    case "url-encode":
      return encodeURIComponent(payload);
    case "json-string-escape":
      return payload.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r");
    case "identity":
    default:
      return payload;
  }
}

/**
 * Convenience builder for the competitor's canonical example chain:
 *   inject in profile  →  trigger in admin panel  →  execute in email
 * Each `param` is the field name where the payload lands at each stage
 * (may differ — profile form stores `bio`, admin panel renders `lastLoginName`,
 * email notification embeds `content`).
 */
export function buildProfileAdminEmailChain(opts: {
  profileInjectUrl: string;
  profileObserveUrl: string;
  adminObserveUrl: string;
  adminCookie: string;
  emailInboxUrl: string;
  victimParam: string;
  profileParam: string;
  adminParam: string;
  emailParam: string;
  victimCookie?: string;
}): StoredXssStage[] {
  return [
    {
      name: "profile",
      injectUrl: opts.profileInjectUrl,
      observeUrl: opts.profileObserveUrl,
      cookie: opts.victimCookie,
      formData: { [opts.profileParam]: opts.victimParam },
      payloadTransform: "identity"
    },
    {
      name: "admin-panel",
      injectUrl: opts.profileInjectUrl,
      observeUrl: opts.adminObserveUrl,
      cookie: opts.adminCookie,
      formData: { [opts.profileParam]: opts.victimParam },
      payloadTransform: "identity"
    },
    {
      name: "email-notification",
      injectUrl: opts.profileInjectUrl,
      observeUrl: opts.emailInboxUrl,
      cookie: opts.adminCookie,
      formData: { [opts.profileParam]: opts.victimParam },
      payloadTransform: "json-string-escape"
    }
  ];
}
