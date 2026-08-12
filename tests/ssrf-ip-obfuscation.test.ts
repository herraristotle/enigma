import { test } from "node:test";
import assert from "node:assert";
import { generateIpObfuscations } from "../core/engines/ssrf/bypasses/ip-obfuscation.ts";

test("IP Obfuscation Techniques", async (t) => {
  const ip = "127.0.0.1";
  const obfuscations = generateIpObfuscations(ip);

  const getHost = (tech: string) => {
    const found = obfuscations.find(o => o.technique === tech);
    if (!found) {
      throw new Error(`Technique not found: ${tech}`);
    }
    return found.host;
  };

  await t.test("decimal", () => {
    assert.strictEqual(getHost("decimal"), "2130706433");
  });

  await t.test("octal dotted", () => {
    assert.strictEqual(getHost("octal dotted"), "0177.0.0.1");
  });

  await t.test("hex integer", () => {
    assert.strictEqual(getHost("hex integer"), "0x7f000001");
  });

  await t.test("hex dotted", () => {
    assert.strictEqual(getHost("hex dotted"), "0x7f.0x0.0x0.0x1");
  });

  await t.test("IPv6 mapped", () => {
    const host = getHost("IPv6 mapped");
    assert.ok(host === "[::ffff:127.0.0.1]" || host === "[::ffff:7f00:1]", `Got: ${host}`);
  });

  await t.test("IPv6 full", () => {
    assert.strictEqual(getHost("IPv6 full"), "[0000:0000:0000:0000:0000:ffff:7f00:0001]");
  });

  await t.test("zero-padded", () => {
    assert.strictEqual(getHost("zero-padded"), "0127.000.000.001");
  });

  await t.test("url-encoded", () => {
    assert.strictEqual(getHost("url-encoded"), "%31%32%37%2E%30%2E%30%2E%31");
  });

  await t.test("mixed-encoding", () => {
    // 0177.0x00.0.1
    assert.strictEqual(getHost("mixed-encoding"), "0177.0x00.0.1");
  });

  await t.test("shortened", () => {
    assert.strictEqual(getHost("shortened"), "127.1");
  });

  await t.test("localhost DNS aliases", () => {
    const found = obfuscations.filter(o => o.technique === "localhost DNS aliases");
    assert.ok(found.length > 0);
    const hosts = found.map(o => o.host);
    assert.ok(hosts.includes("localtest.me"));
    assert.ok(hosts.includes("127.0.0.1.nip.io"));
    // De-duplication guard — every DNS alias must be unique.
    const unique = new Set(hosts);
    assert.strictEqual(unique.size, hosts.length, `Duplicate DNS alias hosts: ${JSON.stringify(hosts)}`);
  });
});

test("IP Obfuscation Env Override (ENIGMA_EXTRA_LOCALHOST_DNS)", () => {
  // Save and restore env so this test is isolated.
  const prev = process.env.ENIGMA_EXTRA_LOCALHOST_DNS;
  try {
    process.env.ENIGMA_EXTRA_LOCALHOST_DNS = "lab-internal.test, custom.rebind.local,";
    const obf = generateIpObfuscations("127.0.0.1");
    const dns = obf.filter(o => o.technique === "localhost DNS aliases").map(o => o.host);
    assert.ok(dns.includes("lab-internal.test"), "Operator-supplied DNS alias should appear");
    assert.ok(dns.includes("custom.rebind.local"), "Second operator DNS alias should appear");
    // No empty-string entries from trailing commas.
    assert.ok(!dns.some(h => h === ""), "Empty alias must not be emitted");
  } finally {
    if (prev === undefined) delete process.env.ENIGMA_EXTRA_LOCALHOST_DNS;
    else process.env.ENIGMA_EXTRA_LOCALHOST_DNS = prev;
  }
});

test("IP Obfuscation Invalid Inputs", () => {
  const invalidIps = [
    "256.0.0.1",
    "127.0.0.300",
    "127.0.0",
    "127.0.0.1.2",
    "127.0.0.1a",
    "abc.def.ghi.jkl",
    "-1.0.0.1",
    "",
    "127.0.0. 1",
  ];

  for (const ip of invalidIps) {
    const results = generateIpObfuscations(ip);
    assert.strictEqual(results.length, 0, `IP ${ip} should be invalid and return empty array`);
  }
});
