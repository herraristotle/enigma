/**
 * DOM XSS: Sink Hooks — 30+ DOM sink interception hooks.
 *
 * "For DOM-based XSS, Enigma injects a monitoring script into every page via
 * Playwright's addInitScript(). This script monkey-patches 30+
 * dangerous DOM APIs to track taint flow."
 *
 * Categories of sinks hooked:
 *  - HTML injection: innerHTML, outerHTML, document.write, insertAdjacentHTML
 *  - Script execution: eval, Function(), setTimeout(string), setInterval(string)
 *  - Navigation: location.href, location.assign, location.replace
 *  - jQuery: $().html(), $().append(), $() constructor (selector injection)
 *
 * Tricky edge case: location.href = 'javascript:alert(1)' navigates away,
 * destroying all in-memory JS state including monitoring hooks.
 * Solution: serialize sink events to sessionStorage before navigation,
 * then recover data after the new page loads.
 */

const DOM_SINKS = [
  "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "document.writeln",
  "eval", "Function", "setTimeout", "setInterval", "location.href", "location.assign",
  "location.replace", "Element.prototype.setAttribute", "HTMLScriptElement.prototype.src",
  "HTMLIFrameElement.prototype.src", "HTMLIFrameElement.prototype.srcdoc", "window.open",
  "history.pushState", "history.replaceState", "jQuery.html", "jQuery.append", "jQuery.prepend",
  "jQuery.before", "jQuery.after", "Element.prototype.innerHTML", "Element.prototype.outerHTML",
  "Range.prototype.createContextualFragment", "DOMParser.parseFromString", "insertRule",
  "createElement", "createTextNode", "appendChild", "replaceChild"
];

export function buildSinkHookScript(): string {
  return `
    (() => {
      const ENIGMA_KEY = "__enigma_sink_events__";
      const ENIGMA_XSS_CONFIRMED = "__enigma_xss_confirmed__";

      // ── Persistence layer ───────────────────────────────────────────
      // Serialize sink events to sessionStorage before navigation,
      // recover after new page loads.
      const persist = (entry) => {
        try {
          const current = JSON.parse(sessionStorage.getItem(ENIGMA_KEY) || "[]");
          current.push({ ...entry, ts: Date.now() });
          sessionStorage.setItem(ENIGMA_KEY, JSON.stringify(current));
        } catch (_) { /* quota exceeded or iframe sandbox */ }
      };

      const confirmXss = (method, value) => {
        persist({ type: method, value: String(value), xssConfirmed: true });
        try {
          sessionStorage.setItem(ENIGMA_XSS_CONFIRMED, JSON.stringify({
            method,
            value: String(value).slice(0, 500),
            ts: Date.now()
          }));
        } catch (_) {}
      };

      // ── Function wrapping helper ────────────────────────────────────
      const wrapFunction = (objectRef, key, type) => {
        if (!objectRef) return;
        const original = objectRef[key];
        if (typeof original !== "function") return;
        objectRef[key] = function (...args) {
          persist({ type, args: args.map(String).slice(0, 3) });
          return original.apply(this, args);
        };
      };

      // ── Script execution sinks ──────────────────────────────────────
      wrapFunction(document, "write", "document.write");
      wrapFunction(document, "writeln", "document.writeln");
      wrapFunction(window, "eval", "eval");
      wrapFunction(window, "setTimeout", "setTimeout");
      wrapFunction(window, "setInterval", "setInterval");

      // Function constructor
      const OriginalFunction = window.Function;
      window.Function = function (...args) {
        persist({ type: "Function", args: args.map(String).slice(0, 3) });
        return OriginalFunction.apply(this, args);
      };
      window.Function.prototype = OriginalFunction.prototype;

      // ── Navigation sinks ────────────────────────────────────────────
      wrapFunction(history, "pushState", "history.pushState");
      wrapFunction(history, "replaceState", "history.replaceState");

      // window.open
      const origOpen = window.open;
      if (origOpen) {
        window.open = function (...args) {
          persist({ type: "window.open", args: args.map(String).slice(0, 3) });
          return origOpen.apply(this, args);
        };
      }

      // location.assign / location.replace
      try {
        const origAssign = window.location.assign.bind(window.location);
        window.location.assign = (value) => {
          confirmXss("location.assign", value);
          return origAssign(value);
        };
      } catch (_) {}

      try {
        const origReplace = window.location.replace.bind(window.location);
        window.location.replace = (value) => {
          confirmXss("location.replace", value);
          return origReplace(value);
        };
      } catch (_) {}

      // location.href can't be reliably hooked via monkey-patching —
      // navigation fires at engine level. Best-effort setter hook; CDP handles the rest.
      try {
        const locationHrefDesc = Object.getOwnPropertyDescriptor(window.location, "href")
          || Object.getOwnPropertyDescriptor(Location.prototype, "href");
        if (locationHrefDesc && locationHrefDesc.set) {
          const origSet = locationHrefDesc.set;
          Object.defineProperty(window.location, "href", {
            set(value) {
              confirmXss("location.href", value);
              return origSet.call(this, value);
            },
            get: locationHrefDesc.get,
            configurable: true
          });
        }
      } catch (_) { /* cross-origin or frozen */ }

      // ── HTML injection sinks ────────────────────────────────────────
      const hookPropertySetter = (proto, prop, type) => {
        try {
          const desc = Object.getOwnPropertyDescriptor(proto, prop);
          if (desc && desc.set) {
            const origSet = desc.set;
            Object.defineProperty(proto, prop, {
              set(value) {
                persist({ type, value: String(value).slice(0, 500) });
                return origSet.call(this, value);
              },
              get: desc.get,
              configurable: true
            });
          }
        } catch (_) {}
      };

      hookPropertySetter(Element.prototype, "innerHTML", "innerHTML");
      hookPropertySetter(Element.prototype, "outerHTML", "outerHTML");

      // insertAdjacentHTML
      try {
        const origInsert = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function (position, text) {
          persist({ type: "insertAdjacentHTML", value: String(text).slice(0, 500) });
          return origInsert.call(this, position, text);
        };
      } catch (_) {}

      // ── Attribute sinks (href, src, srcdoc via setAttribute) ────────
      try {
        const origSetAttribute = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function (name, value) {
          const dangerous = ["href", "src", "srcdoc", "action", "formaction", "data", "xlink:href"];
          if (dangerous.includes(name.toLowerCase())) {
            persist({ type: "setAttribute:" + name, value: String(value).slice(0, 500) });
          }
          return origSetAttribute.call(this, name, value);
        };
      } catch (_) {}

      // Script src property
      hookPropertySetter(HTMLScriptElement.prototype, "src", "script.src");

      // Iframe src / srcdoc
      hookPropertySetter(HTMLIFrameElement.prototype, "src", "iframe.src");
      hookPropertySetter(HTMLIFrameElement.prototype, "srcdoc", "iframe.srcdoc");

      // ── Range / DOMParser ───────────────────────────────────────────
      try {
        const origFragment = Range.prototype.createContextualFragment;
        Range.prototype.createContextualFragment = function (markup) {
          persist({ type: "createContextualFragment", value: String(markup).slice(0, 500) });
          return origFragment.call(this, markup);
        };
      } catch (_) {}

      try {
        const origParse = DOMParser.prototype.parseFromString;
        DOMParser.prototype.parseFromString = function (str, type) {
          persist({ type: "DOMParser.parseFromString", value: String(str).slice(0, 500) });
          return origParse.call(this, str, type);
        };
      } catch (_) {}

      // ── jQuery sinks ────────────────────────────────────────────────
      const hookJQuery = () => {
        const $ = window.jQuery || window.$;
        if (!$ || !$.fn) return;

        const jqMethods = ["html", "append", "prepend", "before", "after", "replaceWith"];
        for (const method of jqMethods) {
          const orig = $.fn[method];
          if (typeof orig !== "function") continue;
          $.fn[method] = function (...args) {
            if (args.length > 0 && typeof args[0] === "string") {
              persist({ type: "jQuery." + method, value: String(args[0]).slice(0, 500) });
            }
            return orig.apply(this, args);
          };
        }

        // $() constructor — selector injection
        const origInit = $.fn.init;
        if (typeof origInit === "function") {
          $.fn.init = function (selector, context, root) {
            if (typeof selector === "string" && /</.test(selector)) {
              persist({ type: "jQuery.constructor", value: selector.slice(0, 500) });
            }
            return new origInit(selector, context, root);
          };
          $.fn.init.prototype = origInit.prototype;
        }
      };

      // Try immediately and also after DOM ready (jQuery may load late)
      hookJQuery();
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", hookJQuery);
      }

      // ── Public API for Enigma runner ────────────────────────────────
      window.__enigmaGetSinkEvents = () => {
        try {
          return JSON.parse(sessionStorage.getItem(ENIGMA_KEY) || "[]");
        } catch (_) { return []; }
      };
      window.__enigmaGetXssConfirmation = () => {
        try {
          return JSON.parse(sessionStorage.getItem(ENIGMA_XSS_CONFIRMED) || "null");
        } catch (_) { return null; }
      };
      window.__enigmaSinkCatalog = ${JSON.stringify(DOM_SINKS)};
    })();
  `;
}
