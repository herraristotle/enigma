import { test } from "node:test";
import assert from "node:assert";
import { applyEncoder, selectiveEncode, inferEffectiveEncodings } from "../core/engines/mutation/encoders.ts";
import { jsfuckEncode } from "../core/engines/mutation/structures.ts";

test("Encoder transforms", async (t) => {
  await t.test("html_decimal", () => {
    assert.strictEqual(applyEncoder("<", "html_decimal"), "&#60;");
  });

  await t.test("html_hex", () => {
    assert.strictEqual(applyEncoder("<", "html_hex"), "&#x3c;");
  });

  await t.test("js_unicode", () => {
    assert.strictEqual(applyEncoder("<", "js_unicode"), "\\u003c");
  });

  await t.test("js_hex", () => {
    assert.strictEqual(applyEncoder("<", "js_hex"), "\\x3c");
  });

  await t.test("url", () => {
    assert.strictEqual(applyEncoder(" ", "url"), "%20");
  });
});

test("Selective encoding", () => {
  const payload = "<img src=x onerror=alert(1)>";
  const blocked = new Set(["<", ">"]);
  
  const result = selectiveEncode(payload, blocked, "html_decimal");
  assert.strictEqual(result, "&#60;img src=x onerror=alert(1)&#62;");
});

test("Infer effective encodings", async (t) => {
  await t.test("Angle bracket blocked", () => {
    const blocked = new Map([["angle", new Set(["<"])]]);
    const inferred = inferEffectiveEncodings(blocked, "html_content");
    
    assert.ok(inferred.includes("html_decimal"));
    assert.ok(inferred.includes("html_hex"));
  });

  await t.test("Script context", () => {
    const blocked = new Map([["quote", new Set(["'"])]]);
    const inferred = inferEffectiveEncodings(blocked, "script_string");
    
    assert.ok(inferred.includes("js_unicode"));
    assert.ok(inferred.includes("js_hex"));
  });
});

test("JSFuck encoding", () => {
  const payload = "alert1";
  const encoded = jsfuckEncode(payload);
  
  // Verify it only uses the 6 JSFuck characters
  assert.ok(/^[()[\]!+]+$/.test(encoded), "Output contains invalid characters");
  
  // Verify length expanded significantly (JSFuck is large)
  assert.ok(encoded.length > 100);
});
