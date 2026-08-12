import { test } from "node:test";
import assert from "node:assert";
import { scoreSsrfFeature, formatTargetConfig, buildCaidoQuery, discoverSsrfSurfaces } from "../cli/commands/ssrf/discover.ts";

test("SSRF Feature Scoring Priority", () => {
  // Priority: webhook (highest/1) -> proxy/fetcher (2) -> PDF (3) -> image (4) -> import/export (5) -> redirect (6) -> API integration (7) -> DNS lookup (lowest/8)
  const webhookScore = scoreSsrfFeature("webhook", "url");
  const proxyScore = scoreSsrfFeature("proxy", "url");
  const pdfScore = scoreSsrfFeature("pdf", "url");
  const imageScore = scoreSsrfFeature("image", "url");
  const importScore = scoreSsrfFeature("import", "url");
  const redirectScore = scoreSsrfFeature("redirect", "url");
  const apiScore = scoreSsrfFeature("api", "url");
  const dnsScore = scoreSsrfFeature("dns", "url");

  assert.ok(webhookScore > proxyScore, `webhook (${webhookScore}) should be > proxy (${proxyScore})`);
  assert.ok(proxyScore > pdfScore, `proxy (${proxyScore}) should be > pdf (${pdfScore})`);
  assert.ok(pdfScore > imageScore, `pdf (${pdfScore}) should be > image (${imageScore})`);
  assert.ok(imageScore > importScore, `image (${imageScore}) should be > import (${importScore})`);
  assert.ok(importScore > redirectScore, `import (${importScore}) should be > redirect (${redirectScore})`);
  assert.ok(redirectScore > apiScore, `redirect (${redirectScore}) should be > api (${apiScore})`);
  assert.ok(apiScore > dnsScore, `api (${apiScore}) should be > dns (${dnsScore})`);
});

test("Parameter-specific scoring adjustment", () => {
  // url, callback, dest, source, proxy, forward score high
  const highParams = ["url", "callback", "dest", "source", "proxy", "forward"];
  const lowParams = ["id", "username", "page", "section"];

  for (const p of highParams) {
    const scoreWithHigh = scoreSsrfFeature("webhook", p);
    const scoreWithLow = scoreSsrfFeature("webhook", "section");
    assert.ok(scoreWithHigh > scoreWithLow, `Param ${p} should increase score compared to section`);
  }
});

test("Target configuration formatting", () => {
  // Correctly formats enigma-ssrf run commands
  const config = {
    url: "https://target.com/api/fetch",
    parameter: "url",
    type: "query" as const,
    score: 95,
  };
  const command = formatTargetConfig(config);
  assert.strictEqual(command, `enigma-ssrf run "https://target.com/api/fetch" "url"`);

  const bodyConfig = {
    url: "https://target.com/api/pdf",
    parameter: "source",
    type: "body" as const,
    score: 85,
  };
  const bodyCommand = formatTargetConfig(bodyConfig);
  assert.strictEqual(bodyCommand, `enigma-ssrf run "https://target.com/api/pdf" "source"`);
});

test("Caido GraphQL HTTPQL filter building", () => {
  // Accepts --httpql and builds correct query filter.
  // Standard target query: "host.like:\"%target.com%\""
  // When httpql provided, should be parsed and combined.
  const queryWithoutHttpql = buildCaidoQuery("target.com");
  assert.ok(queryWithoutHttpql.includes(`host.like:"%target.com%"`));

  const queryWithHttpql = buildCaidoQuery("target.com", `method:"POST"`);
  assert.ok(queryWithHttpql.includes(`host.like:"%target.com%"`));
  assert.ok(queryWithHttpql.includes(`method:"POST"`));
});

test("discoverSsrfSurfaces handles fallback gracefully when Caido fails", async () => {
  // Return mock values if fetch fails or Caido unavailable
  const results = await discoverSsrfSurfaces("target.com", "http://invalid-caido-endpoint/graphql");
  assert.ok(results.length > 0);
  assert.ok(results[0].score > 0);
  assert.ok(results[0].command.startsWith("enigma-ssrf run"));
});
