export interface CaidoRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  query: string;
}

export interface InjectionSurface {
  url: string;
  parameter: string;
  type: "query" | "header" | "body" | "path" | "cookie";
  score: number;
  rationale: string;
  command: string;
}

/**
 * Enigma Discover: Caido Integration
 *
 * "Instead of passing a literal URL, an operator can type: enigma discover <target.com>
 * Enigma queries Caido's GraphQL API, extracts all historical requests to that target,
 * identifies injection points (URL parameters, headers like Referer/User-Agent, JSON body keys),
 * scores them for XSS likelihood, and outputs ready-to-copy `enigma run` commands."
 */
export async function discoverSurfaces(target: string, caidoEndpoint = "http://127.0.0.1:8080/graphql", caidoToken = ""): Promise<InjectionSurface[]> {
  try {
    const requests = await fetchCaidoRequests(target, caidoEndpoint, caidoToken);
    const surfaces: InjectionSurface[] = [];

    for (const req of requests) {
      const urlObj = new URL(req.url);

      // 1. Query Parameters
      for (const [key, value] of new URLSearchParams(req.query).entries()) {
        const { score, rationale } = scoreInjectionPoint(key, value, "query");
        surfaces.push({
          url: req.url,
          parameter: key,
          type: "query",
          score,
          rationale,
          command: \`enigma run "\${urlObj.origin}\${urlObj.pathname}" "\${key}"\`
        });
      }

      // 2. Interesting Headers
      const targetHeaders = ["referer", "user-agent", "x-forwarded-for", "host", "origin"];
      for (const header of targetHeaders) {
        if (req.headers[header]) {
          surfaces.push({
            url: req.url,
            parameter: header,
            type: "header",
            score: 60,
            rationale: \`Commonly logged or reflected header: \${header}\`,
            command: \`enigma run "\${req.url}" "\${header}" --inject-header="\${header}"\`
          });
        }
      }

      // 3. Cookies
      if (req.headers["cookie"]) {
        const cookies = req.headers["cookie"].split(";").map(c => c.trim().split("=")[0]);
        for (const cookie of cookies) {
          if (cookie.length > 0) {
            surfaces.push({
              url: req.url,
              parameter: cookie,
              type: "cookie",
              score: 40,
              rationale: "Cookie value might be reflected or used in DOM",
              command: \`enigma run "\${req.url}" "\${cookie}" --cookie="\${req.headers["cookie"]}"\`
            });
          }
        }
      }

      // 4. JSON Body (simplified)
      if (req.headers["content-type"]?.includes("application/json") && req.body) {
        try {
          const bodyObj = JSON.parse(req.body);
          for (const key of Object.keys(bodyObj)) {
            surfaces.push({
              url: req.url,
              parameter: key,
              type: "body",
              score: 75,
              rationale: "JSON body parameter",
              command: \`enigma run "\${req.url}" "\${key}"\` // Needs POST adapter in runner
            });
          }
        } catch (_) { /* invalid json */ }
      }

      // 5. Form Body
      if (req.headers["content-type"]?.includes("application/x-www-form-urlencoded") && req.body) {
        for (const [key, value] of new URLSearchParams(req.body).entries()) {
           surfaces.push({
            url: req.url,
            parameter: key,
            type: "body",
            score: 80,
            rationale: \`Form parameter (\${value.length > 50 ? 'long' : 'short'})\`,
            // Provide a stored XSS example command
            command: \`enigma run "\${urlObj.origin}\${urlObj.pathname}" "\${key}" --form="\${req.body}" --observe="\${urlObj.origin}/"\`
          });
        }
      }

      // 6. Path Segments (DOM XSS / Hash)
      surfaces.push({
        url: req.url,
        parameter: "hash",
        type: "path",
        score: 50,
        rationale: "Location hash for DOM XSS",
        command: \`enigma run "\${req.url}" "hash" --source=hash\`
      });
    }

    // Sort by descending score and deduplicate commands
    const uniqueCommands = new Set<string>();
    return surfaces
      .sort((a, b) => b.score - a.score)
      .filter((s) => {
        if (uniqueCommands.has(s.command)) return false;
        uniqueCommands.add(s.command);
        return true;
      });

  } catch (error: any) {
    console.warn(\`Caido integration unavailable: \${error.message}\`);
    console.warn("Returning mock data for demonstration.");
    return [
      {
        url: \`https://\${target}/search?q=test\`,
        parameter: "q",
        type: "query",
        score: 90,
        rationale: "Search query parameter (highly likely to reflect)",
        command: \`enigma run "https://\${target}/search" "q"\`
      },
      {
        url: \`https://\${target}/profile\`,
        parameter: "bio",
        type: "body",
        score: 85,
        rationale: "Profile bio form field (potential stored XSS)",
        command: \`enigma run "https://\${target}/profile" "bio" --form="bio=test&user=1" --observe="https://\${target}/user/1"\`
      }
    ];
  }
}

function scoreInjectionPoint(key: string, value: string, type: string): { score: number, rationale: string } {
  let score = 50;
  let rationale = "Standard parameter";

  key = key.toLowerCase();
  if (["q", "query", "search", "keyword", "s"].includes(key)) {
    score += 40;
    rationale = "Search parameter (highly likely to reflect)";
  } else if (["url", "redirect", "next", "return", "page", "callback", "href"].includes(key)) {
    score += 35;
    rationale = "Common redirect/link parameter (DOM XSS / javascript: URI focus)";
  } else if (["id", "uuid", "token", "hash"].includes(key)) {
    score -= 30;
    rationale = "Likely an identifier (low reflection probability)";
  } else if (value.length > 100) {
    score += 20;
    rationale = "Long parameter (often reflected as content)";
  }

  return { score: Math.min(100, Math.max(0, score)), rationale };
}

async function fetchCaidoRequests(target: string, endpoint: string, token: string): Promise<CaidoRequest[]> {
  // Try to connect to Caido GraphQL API
  const query = \`
    query {
      requests(filter: { host: { like: "%\${target}%" } }, first: 50) {
        edges {
          node {
            id
            request {
              url
              method
              headers { name value }
              body
              query
            }
          }
        }
      }
    }
  \`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": \`Bearer \${token}\` } : {})
    },
    body: JSON.stringify({ query })
  });
  
  if (!response.ok) {
     throw new Error(\`GraphQL HTTP Error: \${response.status}\`);
  }

  const { data } = await response.json();
  if (!data || !data.requests) return [];

  return data.requests.edges.map((edge: any) => {
    const req = edge.node.request;
    const headers: Record<string, string> = {};
    for (const h of req.headers || []) {
      headers[h.name.toLowerCase()] = h.value;
    }
    
    // Parse query string manually if Caido doesn't separate it
    let queryObj = req.query || "";
    if (!queryObj && req.url.includes("?")) {
        queryObj = req.url.split("?")[1];
    }
    
    // We attempt to decode the body assuming it's UTF-8 text for simplicity
    // A robust implementation would handle encoding and binary data properly
    let bodyText = req.body || "";
    if (typeof bodyText === "string" && bodyText.startsWith("eyJ")) {
       // Just a heuristic to skip obvious base64 binary blobs if they appear
    }

    return {
      id: edge.node.id,
      url: req.url,
      method: req.method,
      headers,
      body: bodyText,
      query: queryObj
    };
  });
}

// CLI Entrypoint
async function main() {
  const target = process.argv[2];
  if (!target) {
    console.error("usage: enigma discover <target.com> [--endpoint=url] [--token=jwt]");
    process.exitCode = 1;
    return;
  }

  let endpoint = "http://127.0.0.1:8080/graphql";
  let token = "";

  for (const arg of process.argv.slice(3)) {
    if (arg.startsWith("--endpoint=")) endpoint = arg.split("=")[1];
    else if (arg.startsWith("--token=")) token = arg.split("=")[1];
  }

  console.log(\`[*] Discovering injection surfaces for \${target} via Caido (\${endpoint})...\`);
  const surfaces = await discoverSurfaces(target, endpoint, token);

  if (surfaces.length === 0) {
    console.log("[-] No surfaces found.");
    return;
  }

  console.log(\`\n[+] Found \${surfaces.length} high-probability injection points:\n\`);

  for (const s of surfaces.slice(0, 10)) { // Top 10
    const color = s.score >= 80 ? "\x1b[31m" : s.score >= 50 ? "\x1b[33m" : "\x1b[32m"; // Red, Yellow, Green
    console.log(\`\${color}[Score: \${s.score.toString().padStart(3, " ")}]\x1b[0m \${s.type.toUpperCase()}: \${s.parameter}\`);
    console.log(\`    Rationale: \${s.rationale}\`);
    console.log(\`    Command:   \x1b[36m\${s.command}\x1b[0m\`);
    console.log("-".repeat(60));
  }
}

// Only run CLI entrypoint if executed directly directly (not imported)
if (import.meta.url === \`file://\${process.argv[1]}\`) {
  void main();
}
