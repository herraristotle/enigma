/**
 * Rotor 3: Encoding — Character representation transforms.
 *
 * "When specific characters are blocked, encoding transforms their
 * representation.  The key insight about encoding: it only works when there's
 * a decode step between the WAF check and the browser rendering."
 *
 * The composer infers encoding effectiveness from the binary search results —
 * if < is blocked as a literal but HTML entities in the same response are
 * decoded by the browser, the engine knows to apply HTML encoding.
 */

export type EncoderName =
  | "html_decimal"
  | "html_hex"
  | "html_named"
  | "html_no_semicolon"
  | "html_leading_zero"
  | "js_unicode"
  | "js_hex"
  | "url"
  | "double_url"
  | "base64";

export const ENCODER_ORDER: EncoderName[] = [
  "html_decimal",
  "html_hex",
  "html_named",
  "html_no_semicolon",
  "html_leading_zero",
  "js_unicode",
  "js_hex",
  "url",
  "double_url",
  "base64"
];

/**
 * Apply a full-payload encoding transform.
 */
export function applyEncoder(value: string, encoder: EncoderName): string {
  switch (encoder) {
    case "html_decimal":
      return [...value].map((char) => `&#${char.charCodeAt(0)};`).join("");
    case "html_hex":
      return [...value].map((char) => `&#x${char.charCodeAt(0).toString(16)};`).join("");
    case "html_named":
      return value.replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
    case "html_no_semicolon":
      return [...value].map((char) => `&#${char.charCodeAt(0)}`).join("");
    case "html_leading_zero":
      return [...value].map((char) => `&#000${char.charCodeAt(0)};`).join("");
    case "js_unicode":
      return [...value].map((char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
    case "js_hex":
      return [...value].map((char) => `\\x${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join("");
    case "url":
      return encodeURIComponent(value);
    case "double_url":
      return encodeURIComponent(encodeURIComponent(value));
    case "base64":
      return Buffer.from(value, "utf8").toString("base64");
    default:
      return value;
  }
}

/**
 * Selectively encode only the characters that are known to be blocked,
 * leaving the rest as-is.  This produces smaller, more targeted payloads.
 */
export function selectiveEncode(
  value: string,
  blockedChars: Set<string>,
  encoder: EncoderName
): string {
  return [...value]
    .map((ch) => (blockedChars.has(ch) ? applyEncoder(ch, encoder) : ch))
    .join("");
}

/**
 * Given the set of blocked character families from the binary search,
 * infer which encodings are likely to be effective.
 *
 * Rules:
 *  - angle/quote blocked → HTML entity encodings likely effective
 *  - Used inside <script> → JS unicode/hex encodings likely effective
 *  - Generic blocked chars → URL encoding worth trying
 */
export function inferEffectiveEncodings(
  blockedFamilies: Map<string, Set<string>>,
  context: string
): EncoderName[] {
  const effective: EncoderName[] = [];
  const hasAngle = (blockedFamilies.get("angle") ?? new Set()).size > 0;
  const hasQuote = (blockedFamilies.get("quote") ?? new Set()).size > 0;
  const isScript = context.startsWith("script_");
  const isSvg = context.startsWith("svg_");

  if (hasAngle || hasQuote) {
    effective.push("html_decimal", "html_hex", "html_named", "html_no_semicolon", "html_leading_zero");
  }
  if (isScript) {
    effective.push("js_unicode", "js_hex");
  }
  if (isSvg) {
    // SVG context: HTML entities in <script> tags are decoded before execution
    effective.push("html_decimal", "html_hex");
  }
  effective.push("url", "double_url");

  // Deduplicate while preserving order
  return [...new Set(effective)];
}

/**
 * Layered encoding: chain multiple encoders in sequence.
 * Each encoder is applied to the output of the previous one.
 */
export function encodeLayered(value: string, layers: EncoderName[]): string {
  return layers.reduce((acc, encoder) => applyEncoder(acc, encoder), value);
}

/**
 * Wrap a payload as a base64 data URI.
 */
export function toBase64DataUrl(payload: string, mimeType = "text/html"): string {
  const encoded = Buffer.from(payload, "utf8").toString("base64");
  return `data:${mimeType};base64,${encoded}`;
}

/* Convenience exports matching competitor's named API */
export const encodeHtmlDecimal = (v: string) => applyEncoder(v, "html_decimal");
export const encodeHtmlHex = (v: string) => applyEncoder(v, "html_hex");
export const encodeHtmlLeadingZeros = (v: string) => applyEncoder(v, "html_leading_zero");
export const encodeJsUnicode = (v: string) => applyEncoder(v, "js_unicode");
export const encodeDoubleUrl = (v: string) => applyEncoder(v, "double_url");
