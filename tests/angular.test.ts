import { test } from "node:test";
import assert from "node:assert";
import { 
  detectAngularVersion, 
  selectAngularEscapes, 
  ANGULAR_SANDBOX_ESCAPES 
} from "../core/engines/mutation/angular.ts";

test("detectAngularVersion — ng-version attribute", () => {
  const html = '<html ng-version="1.6.10">';
  assert.strictEqual(detectAngularVersion(html), "1.6.10");
});

test("detectAngularVersion — CDN script URL", () => {
  const html = '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js"></script>';
  assert.strictEqual(detectAngularVersion(html), "1.5.8");
});

test("detectAngularVersion — inline angular.version.full", () => {
  const html = '<script>angular.version.full = "1.8.2";</script>';
  assert.strictEqual(detectAngularVersion(html), "1.8.2");
});

test("detectAngularVersion — returns null when not found", () => {
  const html = '<html><body>No Angular here</body></html>';
  assert.strictEqual(detectAngularVersion(html), null);
});

test("selectAngularEscapes — unknown version returns all", () => {
  const escapes = selectAngularEscapes(null);
  assert.strictEqual(escapes.length, ANGULAR_SANDBOX_ESCAPES.length);
});

test("selectAngularEscapes — 1.0-1.5 selects orderBy + window + String + SSR", () => {
  const escapes = selectAngularEscapes("1.4.7");
  const names = escapes.map(e => e.technique);
  assert.ok(names.includes("orderBy toString leak"));
  assert.ok(names.includes("$window eval"));
  assert.ok(names.includes("String.fromCharCode eval"));
  assert.ok(names.includes("SSR template injection"));
  // ng-csp should also be included
  assert.ok(names.includes("ng-csp $on eval"));
});

test("selectAngularEscapes — 1.6 selects constructor + Function.bind + SSR", () => {
  const escapes = selectAngularEscapes("1.6.10");
  const names = escapes.map(e => e.technique);
  assert.ok(names.includes("constructor.constructor eval"));
  assert.ok(names.includes("Function.bind eval"));
  assert.ok(names.includes("SSR template injection"));
});

test("selectAngularEscapes — ng-csp version selects CSP-specific", () => {
  const escapes = selectAngularEscapes("ng-csp");
  const names = escapes.map(e => e.technique);
  assert.ok(names.includes("ng-csp $on eval"));
});

test("ANGULAR_SANDBOX_ESCAPES — has all expected techniques", () => {
  const names = new Set(ANGULAR_SANDBOX_ESCAPES.map(e => e.technique));
  assert.ok(names.has("constructor.constructor eval"));
  assert.ok(names.has("orderBy toString leak"));
  assert.ok(names.has("$window eval"));
  assert.ok(names.has("String.fromCharCode eval"));
  assert.ok(names.has("Function.bind eval"));
  assert.ok(names.has("$on listener eval"));
  assert.ok(names.has("ng-csp $on eval"));
  assert.ok(names.has("SSR template injection"));
  assert.ok(names.has("ng-bind-html escape"));
  assert.ok(names.has("ng-init window leak"));
});