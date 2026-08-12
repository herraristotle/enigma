/**
 * Rotor 2: Blocker Detection — Binary search decomposition and cascade alternatives.
 */

import masterRules from "../../../tests/cascade-rules/MASTER-RULES.json" with { type: "json" };

export interface ComponentObservation {
  family: string;
  value: string;
  blocked: boolean;
  successful: boolean;
  reflected?: boolean;
}

export interface InferredBlocker {
  family: string;
  blockedValues: string[];
  inferredFrom: string[];
}

export const EVENT_CASCADE = [...masterRules.cascades.event];
export const KEYWORD_CASCADE = [...masterRules.cascades.keyword];
export const PAREN_CASCADE = [...masterRules.cascades.paren];
export const SPACE_CASCADE = [...masterRules.cascades.space];
export const TAG_CASCADE = [...masterRules.cascades.tag];
export const SCRIPT_CASCADE = [...masterRules.cascades.script];
export const HREF_CASCADE = [...masterRules.cascades.href];
export const WINDOW_CASCADE = [...masterRules.cascades.window];

export const BLOCKER_PROBES: Array<{ family: string; values: string[] }> = [
  { family: "tag", values: ["<img", "<svg", "<details", "<input", "<math", "<xss"] },
  { family: "event", values: ["onerror", "onload", "ontoggle", "onfocus", "onbegin", "onbeforetoggle"] },
  { family: "keyword", values: ["alert", "confirm", "prompt", "print", "eval"] },
  { family: "paren", values: ["(", ")"] },
  { family: "space", values: [" ", "\t", "\n", "\f", "/**/"] },
  { family: "angle", values: ["<", ">"] },
  { family: "quote", values: ["\"", "'", "`"] },
  { family: "script", values: ["</script>", "\\x3cscript", "\\u003cscript"] },
  { family: "href", values: ["javascript:", "data:", "vbscript:"] },
  { family: "window", values: ["window", "globalThis", "top", "parent", "self"] }
];

export function inferBlockers(observations: ComponentObservation[]): InferredBlocker[] {
  const grouped = new Map<string, ComponentObservation[]>();
  for (const observation of observations) {
    grouped.set(observation.family, [...(grouped.get(observation.family) ?? []), observation]);
  }

  const inferred: InferredBlocker[] = [];
  for (const [family, familyObservations] of grouped) {
    const confirmed = familyObservations.filter((item) => item.blocked).map((item) => item.value);
    if (confirmed.length >= 2) {
      inferred.push({
        family,
        blockedValues: confirmed,
        inferredFrom: familyObservations.map((item) => item.value)
      });
    }
  }
  return inferred;
}

export function shouldPivotToEnumeration(blockedTags: Set<string>, cascadesExhausted: boolean): boolean {
  return blockedTags.size >= masterRules.pivot.blockedTagThreshold || cascadesExhausted;
}

export function buildCascadeAlternatives(family: string): string[] {
  switch (family) {
    case "event":
      return EVENT_CASCADE;
    case "keyword":
      return KEYWORD_CASCADE;
    case "paren":
      return PAREN_CASCADE;
    case "space":
      return SPACE_CASCADE;
    case "tag":
      return TAG_CASCADE;
    case "script":
      return SCRIPT_CASCADE;
    case "href":
      return HREF_CASCADE;
    case "window":
      return WINDOW_CASCADE;
    case "angle":
      return ["<", ">"];
    case "quote":
      return ['"', "'", "`"];
    default:
      return [];
  }
}

export function replaceAlertWith(payload: string, alternative: string): string {
  return payload.replace(/\balert\b/gi, alternative);
}

export function generateRegexExploitVariants(payload: string): string[] {
  const variants: string[] = [];

  // 1. Null byte injection between tag name and event
  variants.push(payload.replace(/(<\w+)(\s)/i, "$1%00$2"));

  // 2. Case alternation
  variants.push(
    payload.replace(/[a-zA-Z]/g, (c, i) =>
      i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()
    )
  );

  // 3. Double whitespace between attributes
  variants.push(payload.replace(/\s+(?=\w+=)/g, "  \t "));

  // 4. Attribute padding — harmless attribute before real ones
  variants.push(payload.replace(/(<\w+)\s/i, "$1 class=x tabindex=1 "));

  // 5. Incomplete tags — strip closing >
  variants.push(payload.replace(/>([^>]*)$/, "//$1"));

  // 6. Nested quotes — swap quote styles
  variants.push(
    payload.replace(/"/g, "'").replace(/'([^']*)'/g, `"$1"`)
  );

  // 7. Unicode whitespace separators (U+00A0, U+2000, U+2003)
  variants.push(payload.replace(/ /g, "\u00A0"));
  variants.push(payload.replace(/ /g, "\u2000"));

  // 8. Backtick attribute boundaries
  variants.push(payload.replace(/=(['"])(.*?)\1/g, "=`$2`"));

  // 9. HTML comments mid-tag between attributes
  variants.push(payload.replace(/\s+(on\w+=)/gi, " <!---->$1"));

  // 10. Chunked keywords — unicode escapes inside keyword
  variants.push(
    payload
      .replace(/alert/gi, "al\\u0065rt")
      .replace(/confirm/gi, "con\\u0066irm")
      .replace(/prompt/gi, "pro\\u006dpt")
  );

  return variants;
}
