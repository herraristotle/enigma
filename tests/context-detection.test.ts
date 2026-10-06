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

describe("detectContext — Heyes contexts (JS for Hackers ch.8)", () => {
  it("detects reflection in an unclosed script (script_no_close)", () => {
    const html = '<script>var q = ENIGMA_PROBE';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "script_no_close");
  });

  it("does not claim closed scripts as script_no_close", () => {
    const html = '<script>var q = "ENIGMA_PROBE";</script>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "script_string_double");
  });

  it("detects reflection in a line comment (script_comment)", () => {
    const html = '<script>init(); // ENIGMA_PROBE\nrun();</script>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "script_comment");
  });

  it("detects reflection in a block comment (script_comment)", () => {
    const html = '<script>/* ENIGMA_PROBE */ run();</script>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "script_comment");
  });

  it("does not treat URL slashes as a comment", () => {
    const html = '<a href="https://example.com/ENIGMA_PROBE">x</a>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "href_attribute");
  });

  it("detects SVG use href reflection (svg_use)", () => {
    const html = '<svg><use href="ENIGMA_PROBE" /></svg>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "svg_use");
  });

  it("detects entity-encoded probe in SVG script (svg_script_entity)", () => {
    const html = '<svg><script>foo&#97; ENIGMA_PROBE</script></svg>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "svg_script_entity");
  });

  it("detects reflection inside an HTML comment (html_comment)", () => {
    const html = '<div><!-- ENIGMA_PROBE --></div>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "html_comment");
  });

  it("detects XHTML namespace documents (xhtml_xml)", () => {
    const html = '<html xmlns="http://www.w3.org/1999/xhtml"><body>ENIGMA_PROBE</body></html>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "xhtml_xml");
  });

  it("detects XML declaration documents (xhtml_xml)", () => {
    const html = '<?xml version="1.0"?><root>ENIGMA_PROBE</root>';
    assert.equal(detectContext(html, "ENIGMA_PROBE"), "xhtml_xml");
  });

  it("detects dynamic import() argument reflection (dynamic_import_sink)", () => {
    const js = 'await import(ENIGMA_PROBE);';
    assert.equal(detectContext(js, "ENIGMA_PROBE"), "dynamic_import_sink");
  });
});