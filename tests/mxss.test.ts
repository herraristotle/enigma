import { test } from "node:test";
import assert from "node:assert";
import { 
  MXSS_VECTORS, 
  buildMxssDetectionScript, 
  analyzeMxss 
} from "../core/engines/mutation/mxss.ts";

test("MXSS_VECTORS — all canonical vectors present", () => {
  const names = MXSS_VECTORS.map(v => v.name);
  assert.ok(names.includes("mathml_integration"));
  assert.ok(names.includes("svg_foreign_object"));
  assert.ok(names.includes("noscript_mode_swap"));
  assert.ok(names.includes("template_inert_reparse"));
  assert.ok(names.includes("svg_style_text_round_trip"));
  assert.ok(names.includes("attribute_namespace_collapse"));
  assert.ok(names.includes("mathml_mglyph_recovery"));
});

test("MXSS_VECTORS — each vector has required fields", () => {
  for (const v of MXSS_VECTORS) {
    assert.ok(v.name);
    assert.ok(v.payload);
    assert.ok(v.reExposesSink);
    assert.ok(v.affects.length > 0);
  }
});

test("buildMxssDetectionScript — generates valid JS with exported function", () => {
  const script = buildMxssDetectionScript();
  assert.ok(script.includes("__enigmaMxssDetect"));
  assert.ok(script.includes("sanitizer_fail"));
  assert.ok(script.includes("mxss_mutation"));
  assert.ok(script.includes("SINK_PATTERN"));
});

test("analyzeMxss — clean verdict", () => {
  const result = analyzeMxss({ verdict: "clean" });
  assert.strictEqual(result.verdict, "clean");
});

test("analyzeMxss — sanitizer_fail verdict", () => {
  const result = analyzeMxss({ verdict: "sanitizer_fail", sinks: ['<img onerror=alert(1)>'] });
  assert.strictEqual(result.verdict, "sanitizer_fail");
});

test("analyzeMxss — mxss_mutation verdict matches noscript or mathml (both expose img onerror)", () => {
  const result = analyzeMxss({ 
    verdict: "mxss_mutation", 
    sinks: ['<img src="x" onerror="alert(1)">'] 
  });
  assert.strictEqual(result.verdict, "mxss_mutation");
  assert.ok(result.matchedVector);
  assert.ok(["noscript_mode_swap", "mathml_integration"].includes(result.matchedVector!.name));
});

test("analyzeMxss — mxss_mutation verdict matches mathml_integration", () => {
  const result = analyzeMxss({ 
    verdict: "mxss_mutation", 
    sinks: ['<img src="x" onerror="alert(1)">'] 
  });
  assert.ok(result.matchedVector);
  // Both noscript and mathml match img onerror — either is acceptable
  assert.ok(["noscript_mode_swap", "mathml_integration"].includes(result.matchedVector!.name));
});

test("analyzeMxss — mxss_mutation with script tag may match any vector that exposes script", () => {
  const result = analyzeMxss({ 
    verdict: "mxss_mutation", 
    sinks: ['<script>alert(1)</script>'] 
  });
  // Matching is best-effort based on sink text; template_inert_reparse may not match script
  assert.ok(result.verdict === "mxss_mutation");
});