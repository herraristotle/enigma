import { test } from "node:test";
import assert from "node:assert";
import { detectStack, generateSsrfPayloadPlan, expandSubnetHosts } from "../core/engines/ssrf/decision-trees.ts";

test("SSRF Decision Trees and Payload Orchestration", async (t) => {
  await t.test("detectStack detects all 7 stacks correctly", () => {
    // PHP
    assert.strictEqual(detectStack({ "X-Powered-By": "PHP/7.4.3" }, ""), "PHP");
    assert.strictEqual(detectStack({ "Set-Cookie": "PHPSESSID=abc" }, ""), "PHP");
    assert.strictEqual(detectStack({}, "Fatal error: Allowed memory size exhausted in /app/index.php on line 12"), "PHP");

    // Python
    assert.strictEqual(detectStack({ "Server": "gunicorn" }, ""), "Python");
    assert.strictEqual(detectStack({ "Server": "Werkzeug/2.0.1 Python/3.8.10" }, ""), "Python");
    assert.strictEqual(detectStack({}, "Traceback (most recent call last):\n  File \"app.py\", line 5, in <module>"), "Python");

    // Node.js
    assert.strictEqual(detectStack({ "X-Powered-By": "Express" }, ""), "Node.js");
    assert.strictEqual(detectStack({ "Set-Cookie": "connect.sid=123" }, ""), "Node.js");
    assert.strictEqual(detectStack({}, "at Server.connectionListener (node:http:500:10)"), "Node.js");

    // Java
    assert.strictEqual(detectStack({ "Server": "Apache-Coyote/1.1" }, ""), "Java");
    assert.strictEqual(detectStack({ "Set-Cookie": "JSESSIONID=abc" }, ""), "Java");
    assert.strictEqual(detectStack({}, "Exception in thread \"main\" java.lang.NullPointerException"), "Java");

    // Ruby
    assert.strictEqual(detectStack({ "Server": "WEBrick/1.6.0" }, ""), "Ruby");
    assert.strictEqual(detectStack({ "Set-Cookie": "_rails_session=abc" }, ""), "Ruby");
    assert.strictEqual(detectStack({}, "NoMethodError: undefined method `name' for nil:NilClass"), "Ruby");

    // .NET
    assert.strictEqual(detectStack({ "X-Powered-By": "ASP.NET" }, ""), ".NET");
    assert.strictEqual(detectStack({ "Set-Cookie": "ASP.NET_SessionId=abc" }, ""), ".NET");
    assert.strictEqual(detectStack({}, "Server Error in '/' Application. runtime error"), ".NET");

    // Go
    assert.strictEqual(detectStack({ "Server": "Go" }, ""), "Go");
    assert.strictEqual(detectStack({}, "panic: runtime error: invalid memory address or nil pointer dereference\ngoroutine 1 [running]:"), "Go");

    // Unknown and edge cases
    assert.strictEqual(detectStack({}, ""), "unknown");
    assert.strictEqual(detectStack({ "X-Custom-Header": "custom-value" }, "some random body"), "unknown");
    assert.strictEqual(detectStack({ "X-PHP-Engine": "5.6" }, ""), "PHP");
    assert.strictEqual(detectStack({ "X-ASP.NET-Version": "4.0" }, ""), ".NET");
    
    // Safety check with non-string headers (casted to any for runtime test)
    assert.strictEqual(detectStack({ "X-Powered-By": null as any }, ""), "unknown");
    assert.strictEqual(detectStack(undefined, undefined), "unknown");
  });

  await t.test("Payload plan option defaults and exclusions", () => {
    // If canaryUrl is omitted, no canary payloads should be generated
    const planNoCanary = generateSsrfPayloadPlan({
      targetUrl: "http://example.com/fetch?url="
    });
    const categoriesNoCanary = planNoCanary.map(p => p.category);
    assert.ok(!categoriesNoCanary.includes("canary"), "Should not generate canary payloads if canaryUrl is omitted");

    // If allowedHost is omitted, it should fallback/default
    const planDefaultAllowed = generateSsrfPayloadPlan({
      targetUrl: "http://example.com/fetch?url="
    });
    // Check that some parser confusion payload has localhost since allowedHost defaults to localhost
    const parserConfusionPayloads = planDefaultAllowed.filter(p => p.category === "parser confusion");
    assert.ok(parserConfusionPayloads.some(p => p.payload.includes("localhost")), "Should fallback to localhost when allowedHost is omitted");

    // If targetUrl is not a full URL or lacks protocol, verify it still works and parses a host
    const planFallbackUrl = generateSsrfPayloadPlan({
      targetUrl: "127.0.0.1/admin"
    });
    const smugglingPayloads = planFallbackUrl.filter(p => p.category === "protocol smuggling");
    assert.ok(smugglingPayloads.length > 0);
  });

  await t.test("Payload plan category ordering", () => {
    const plan = generateSsrfPayloadPlan({
      targetUrl: "http://example.com/fetch?url=",
      allowedHost: "allowed.com",
      canaryUrl: "canary.example.com"
    });

    const categories = plan.map(p => p.category);
    
    // Ensure all categories exist
    assert.ok(categories.includes("localhost admin"));
    assert.ok(categories.includes("cloud metadata"));
    assert.ok(categories.includes("internal service"));
    assert.ok(categories.includes("parser confusion"));
    assert.ok(categories.includes("protocol smuggling"));
    assert.ok(categories.includes("canary"));

    // Verify ordering
    let lastIndex = -1;
    const order = [
      "localhost admin",
      "cloud metadata",
      "internal service",
      "parser confusion",
      "protocol smuggling",
      "canary"
    ];

    for (const cat of order) {
      const firstIdx = categories.indexOf(cat);
      assert.ok(firstIdx !== -1, `Category ${cat} should be present`);
      assert.ok(firstIdx > lastIndex, `Category ${cat} out of order. Index ${firstIdx} should be > ${lastIndex}`);
      lastIndex = categories.lastIndexOf(cat);
    }
  });

  await t.test("Stack-specific bypass ordering prioritizes differently", () => {
    const stacks = ["PHP", "Python", "Node.js", "Java", "Ruby", ".NET", "Go"] as const;
    const orderings: Record<string, string[]> = {};

    for (const stack of stacks) {
      const plan = generateSsrfPayloadPlan({
        targetUrl: "http://example.com/fetch?url=",
        allowedHost: "allowed.com",
        headers: { "X-Powered-By": stack === "Node.js" ? "Express" : stack }
      });

      const parserConfusionTechniques = [
        ...new Set(
          plan
            .filter(p => p.category === "parser confusion")
            .map(p => p.technique || "")
        )
      ];

      assert.ok(parserConfusionTechniques.length > 0, `No parser confusion payloads for ${stack}`);
      orderings[stack] = parserConfusionTechniques;
    }

    // Assert that the orderings differ among all stacks
    for (let i = 0; i < stacks.length; i++) {
      for (let j = i + 1; j < stacks.length; j++) {
        const stackA = stacks[i];
        const stackB = stacks[j];
        assert.notDeepStrictEqual(
          orderings[stackA],
          orderings[stackB],
          `Ordering for ${stackA} and ${stackB} should be different`
        );
      }
    }

    // Assert specific documented rules
    // PHP: fragment, authority first
    const phpOrder = orderings["PHP"];
    assert.strictEqual(phpOrder[0], "fragment confusion");
    assert.strictEqual(phpOrder[1], "authority confusion");

    // Python: backslash, Unicode, fragment first
    const pythonOrder = orderings["Python"];
    assert.strictEqual(pythonOrder[0], "backslash confusion");
    assert.strictEqual(pythonOrder[1], "Unicode normalization");
    assert.strictEqual(pythonOrder[2], "fragment confusion");

    // Node: Unicode, protocol-relative/scheme confusion, CRLF first
    const nodeOrder = orderings["Node.js"];
    assert.strictEqual(nodeOrder[0], "Unicode normalization");
    assert.strictEqual(nodeOrder[1], "scheme confusion");
    assert.strictEqual(nodeOrder[2], "CRLF injection");
  });

  await t.test("expandSubnetHosts handles edge cases correctly", () => {
    // Test IP overflow at 255 boundary
    const hosts = expandSubnetHosts("10.0.0.254/30", 4);
    assert.ok(hosts.includes("10.0.0.255"), "Should include .255");
    assert.ok(hosts.includes("10.0.1.0"), "Should wrap to .1.0");

    // Test /32 single host
    const single = expandSubnetHosts("192.168.1.1/32");
    assert.deepStrictEqual(single, ["192.168.1.1"]);
  });
});
