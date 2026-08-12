import { test } from "node:test";
import assert from "node:assert";
import { 
  parseCspHeader, 
  summarizeCsp, 
  selectCspBypassStrategies,
  scrapeDomNonceScript 
} from "../core/engines/mutation/csp.ts";

test("parseCspHeader — single directive", () => {
  const header = "script-src 'self' 'nonce-abc123' 'strict-dynamic'";
  const parsed = parseCspHeader(header);
  assert.strictEqual(parsed.length, 1);
  assert.strictEqual(parsed[0].name, "script-src");
  assert.deepStrictEqual(parsed[0].sources, ["'self'", "'nonce-abc123'", "'strict-dynamic'"]);
});

test("parseCspHeader — multiple directives", () => {
  const header = "default-src 'self'; script-src 'self' 'nonce-xyz'; style-src 'self' 'unsafe-inline'; object-src 'none'";
  const parsed = parseCspHeader(header);
  assert.ok(parsed.length >= 3);
  const scriptSrc = parsed.find(d => d.name === "script-src");
  assert.ok(scriptSrc);
  assert.ok(scriptSrc.sources.includes("'nonce-xyz'"));
});

test("parseCspHeader — folded header (comma-separated policies)", () => {
  // Multiple headers folded by proxy
  const header = "script-src 'self', script-src 'nonce-abc'";
  const parsed = parseCspHeader(header);
  assert.ok(parsed.length >= 1);
});

test("summarizeCsp — nonce detection", () => {
  const header = "script-src 'self' 'nonce-deadbeef' 'strict-dynamic'; object-src 'none'";
  const summary = summarizeCsp(parseCspHeader(header));
  assert.strictEqual(summary.hasScriptSrc, true);
  assert.strictEqual(summary.hasNonce, true);
  assert.strictEqual(summary.firstNonce, "deadbeef");
  assert.strictEqual(summary.hasStrictDynamic, true);
  assert.strictEqual(summary.hasObjectSrcNone, true);
});

test("summarizeCsp — no nonce", () => {
  const header = "script-src 'self' 'unsafe-inline'; style-src 'self'";
  const summary = summarizeCsp(parseCspHeader(header));
  assert.strictEqual(summary.hasNonce, false);
  assert.strictEqual(summary.hasUnsafeInline, true);
});

test("summarizeCsp — hash sources", () => {
  const header = "script-src 'sha256-abc123' 'sha384-def456'; object-src 'none'";
  const summary = summarizeCsp(parseCspHeader(header));
  assert.strictEqual(summary.hasHash, true);
});

test("summarizeCsp — trusted-types directive", () => {
  const header = "trusted-types default; require-trusted-types-for 'script'; script-src 'self'";
  const summary = summarizeCsp(parseCspHeader(header));
  assert.strictEqual(summary.hasTrustedTypes, true);
  assert.strictEqual(summary.hasRequireTrustedTypesFor, true);
});

test("selectCspBypassStrategies — trusted-types triggers default-policy takeover", () => {
  const header = "trusted-types default; require-trusted-types-for 'script'; script-src 'self'";
  const strategies = selectCspBypassStrategies(header);
  const trustedTypes = strategies.find(s => s.name === "trusted_types_bypass");
  assert.ok(trustedTypes, "must produce trusted_types_bypass strategy");
  assert.ok(trustedTypes.payload.includes("trustedTypes.createPolicy"), "payload must create default policy");
  assert.ok(trustedTypes.rationale.includes("require-trusted-types-for"));
});

test("selectCspBypassStrategies — strict-dynamic triggers trust-loader", () => {
  const header = "script-src 'self' 'nonce-abc' 'strict-dynamic'";
  const strategies = selectCspBypassStrategies(header);
  const strictDynamic = strategies.find(s => s.name === "strict_dynamic_bypass");
  assert.ok(strictDynamic, "must produce strict_dynamic_bypass strategy");
  assert.ok(strictDynamic.payload.includes("document.currentScript"), "payload must use currentScript parentNode chain");
});

test("selectCspBypassStrategies — nonce produces extracted_nonce_reuse", () => {
  const header = "script-src 'self' 'nonce-xyz789'";
  const strategies = selectCspBypassStrategies(header);
  const nonceReuse = strategies.find(s => s.name === "extracted_nonce_reuse");
  assert.ok(nonceReuse, "must produce extracted_nonce_reuse strategy");
  assert.ok(nonceReuse.payload.includes('nonce="xyz789"'), "payload must include scraped nonce value");
});

test("selectCspBypassStrategies — no script-src returns empty", () => {
  const header = "style-src 'self'; img-src 'self'";
  const strategies = selectCspBypassStrategies(header);
  assert.strictEqual(strategies.length, 0);
});

test("selectCspBypassStrategies — empty header returns empty", () => {
  const strategies = selectCspBypassStrategies("");
  assert.strictEqual(strategies.length, 0);
});

test("scrapeDomNonceScript — returns evaluation function", () => {
  const script = scrapeDomNonceScript();
  assert.ok(script.includes("querySelectorAll('script[nonce]')"));
  assert.ok(script.includes("getAttribute('nonce')"));
});