import { test } from "node:test";
import assert from "node:assert";
import { generateIpObfuscations } from "../core/engines/ssrf/bypasses/ip-obfuscation.ts";
import { generateParserConfusionPayloads } from "../core/engines/ssrf/bypasses/parser-confusion.ts";
import { EXECUTION_CASCADE } from "../core/engines/mutation/executors.ts";
import { DOM_CLOBBERING_CANDIDATES } from "../core/engines/mutation/structures.ts";

test("Audit follow-up — Tsai faraday bypass `0` host", () => {
  const obf = generateIpObfuscations("127.0.0.1");
  const decimals = obf.filter(o => o.technique === "decimal").map(o => o.host);
  assert.ok(decimals.includes("0"), `decimal must include faraday bypass '0', got: ${JSON.stringify(decimals)}`);
});

test("Audit follow-up — Tsai parser confusion: multi-@ + port", () => {
  const payloads = generateParserConfusionPayloads("http://169.254.169.254/", "allowed.com");
  const multiAtPort = payloads.filter(p => p.technique === "multiple @ with port");
  assert.ok(multiAtPort.length >= 2, `expected >=2 multi-@ + port payloads, got ${multiAtPort.length}`);
  assert.ok(multiAtPort.some(p => p.payload.includes(":11211@")), "must embed internal port before trailing @");
  assert.ok(multiAtPort.some(p => p.payload.includes(":80")), "must embed allowedHost port after @");
});

test("Audit follow-up — Tsai parser confusion: weird port extra-colon", () => {
  const payloads = generateParserConfusionPayloads("http://169.254.169.254/", "allowed.com");
  const weird = payloads.filter(p => p.technique === "extra colon port");
  assert.ok(weird.some(p => /:11211:80/.test(p.payload)), "must produce :11211:80 weird-port form");
});

test("Audit follow-up — Tsai Glibc whitespace host", () => {
  const payloads = generateParserConfusionPayloads("http://127.0.0.1/", "foo.google.com");
  const glibc = payloads.filter(p => p.technique === "Glibc whitespace host");
  assert.ok(glibc.length >= 3, `expected >=3 Glibc forms, got ${glibc.length}`);
  assert.ok(glibc.some(p => p.payload.includes("\t")), "literal tab form");
  assert.ok(glibc.some(p => p.payload.includes("%09")), "URL-encoded tab form");
  assert.ok(glibc.some(p => p.payload.includes("%2509")), "double URL-encoded tab form");
});

test("Audit follow-up — Tsai RFC1035 \\DDD decimal DNS", () => {
  const payloads = generateParserConfusionPayloads("http://169.254.169.254/", "allowed.com");
  const decimal = payloads.filter(p => p.technique === "RFC1035 decimal DNS");
  assert.ok(decimal.some(p => p.payload.includes("\\097")), "must include \\097 (lowercase 'a') decimal DNS form");
});

test("Audit follow-up — Tsai fullwidth CRLF smuggling", () => {
  const payloads = generateParserConfusionPayloads("http://127.0.0.1:6379/", "evil.com");
  const fw = payloads.filter(p => p.technique === "fullwidth CRLF smuggling");
  assert.ok(fw.length >= 1, "expected fullwidth CRLF payload");
  assert.ok(fw[0].payload.includes("\uFF0D"), "U+FF0D fullwidth hyphen");
  assert.ok(fw[0].payload.includes("\uFF0A"), "U+FF0A fullwidth asterisk");
  assert.ok(fw[0].payload.includes("\uFF40"), "U+FF40 fullwidth commercial-at");
});

test("Audit follow-up — Tsai IDNA zero-width joiner", () => {
  const payloads = generateParserConfusionPayloads("http://169.254.169.254/", "allowed.com");
  const zwj = payloads.filter(p => p.technique === "IDNA zero-width joiner");
  assert.ok(zwj.some(p => p.payload.includes("\u200D")), "must include U+200D ZWJ");
});

test("Audit follow-up — Heyes Ch.8 auto-fire events added", () => {
  const names = new Set(EXECUTION_CASCADE.map(e => e.name));
  const expected = [
    "onunhandledrejection",
    "onpopstate_iframe",
    "onhashchange_iframe",
    "onmessage_iframe",
    "onfocusin_autofocus",
    "ontransitioncancel",
    "onwebkittransitionend",
    "onbeforescriptexecute",
    "animate_onend"
  ];
  for (const name of expected) {
    assert.ok(names.has(name), `EXECUTION_CASCADE missing Heyes Ch.8 vector: ${name}`);
  }
});

test("Audit follow-up — Heyes Ch.4 DOM clobber gadgets added", () => {
  const names = new Set(DOM_CLOBBERING_CANDIDATES.map(c => c.name));
  const expected = [
    "dom_clobber_form_three_level",
    "dom_clobber_attributes",
    "dom_clobber_node_name",
    "dom_clobber_get_element_by_id",
    "dom_clobber_query_selector",
    "dom_clobber_iframe_srcdoc_chain"
  ];
  for (const name of expected) {
    assert.ok(names.has(name), `DOM_CLOBBERING_CANDIDATES missing Heyes Ch.4 gadget: ${name}`);
  }
});

test("Audit follow-up — DOM clobber entries deduplicated", () => {
  const names = DOM_CLOBBERING_CANDIDATES.map(c => c.name);
  const unique = new Set(names);
  assert.strictEqual(unique.size, names.length, `duplicate DOM clobber names: ${JSON.stringify(names)}`);
});
