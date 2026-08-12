import { detectContext, dualProbeSequence } from "../core/engines/mutation/context-techniques.ts";
import { describe, it } from "node:test";
import assert from "node:assert";

describe("dualProbeSequence", () => {
  it("should return probe with angle brackets first", () => {
    const probes = dualProbeSequence("TEST123");
    assert.equal(probes.length, 2);
    assert.ok(probes[0].includes("<"));
    assert.ok(probes[0].includes(">"));
  });

  it("should return alphanumeric-only probe second", () => {
    const probes = dualProbeSequence("TEST123");
    assert.equal(probes.length, 2);
    assert.ok(!probes[1].includes("<"));
    assert.ok(!probes[1].includes(">"));
  });
});

describe("detectContext", () => {
  it("should detect hidden_input context with priority over html_content", () => {
    const html = '<input type="hidden" value="ENIGMA_PROBE">';
    const ctx = detectContext(html, "ENIGMA_PROBE");
    assert.equal(ctx, "hidden_input");
  });

  it("should detect href_attribute context", () => {
    const html = '<a href="javascript:void(0)?q=ENIGMA_PROBE">link</a>';
    const ctx = detectContext(html, "ENIGMA_PROBE");
    assert.equal(ctx, "href_attribute");
  });

  it("should detect srcdoc_attribute context", () => {
    const html = '<iframe srcdoc="<img src=x onerror=alert(1)>ENIGMA_PROBE"></iframe>';
    const ctx = detectContext(html, "ENIGMA_PROBE");
    assert.equal(ctx, "srcdoc_attribute");
  });

  it("should detect script_string_template context", () => {
    const html = '<script>var x = `ENIGMA_PROBE`;</script>';
    const ctx = detectContext(html, "ENIGMA_PROBE");
    assert.equal(ctx, "script_string_template");
  });

  it("should fallback to html_content when no specific context matched", () => {
    const html = '<div>ENIGMA_PROBE</div>';
    const ctx = detectContext(html, "ENIGMA_PROBE");
    assert.equal(ctx, "html_content");
  });
});