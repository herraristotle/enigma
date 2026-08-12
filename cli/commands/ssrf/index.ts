#!/usr/bin/env node
async function main(): Promise<void> {
  const command = process.argv[2];

  if (!command) {
    console.error("usage: enigma-ssrf <command> [options]");
    console.error("commands: discover, run, blind");
    process.exitCode = 1;
    return;
  }

  switch (command) {
    case "discover":
      console.log("Routing to discover command...");
      const target = process.argv[3];
      if (!target) {
        // Just print routing log and break or let routing work
        break;
      }
      const { discoverSsrfSurfaces } = await import("./discover.ts");
      let endpoint = "http://127.0.0.1:8080/graphql";
      let token = "";
      let httpql = "";
      for (const arg of process.argv.slice(4)) {
        if (arg.startsWith("--endpoint=")) endpoint = arg.slice(arg.indexOf("=") + 1);
        else if (arg.startsWith("--token=")) token = arg.slice(arg.indexOf("=") + 1);
        else if (arg.startsWith("--httpql=")) httpql = arg.slice(arg.indexOf("=") + 1);
      }
      const surfaces = await discoverSsrfSurfaces(target, endpoint, token, httpql);
      if (surfaces.length === 0) {
        console.log("[-] No surfaces found.");
      } else {
        console.log(`\n[+] Found ${surfaces.length} candidate SSRF targets:\n`);
        for (const s of surfaces.slice(0, 15)) {
          const color = s.score >= 80 ? "\x1b[31m" : s.score >= 50 ? "\x1b[33m" : "\x1b[32m";
          console.log(`${color}[Score: ${s.score.toString().padStart(3, " ")}]\x1b[0m ${s.type.toUpperCase()}: ${s.parameter} (on ${s.url})`);
          console.log(`    Rationale: ${s.rationale}`);
          console.log(`    Command:   \x1b[36m${s.command}\x1b[0m`);
          console.log("-".repeat(70));
        }
      }
      break;
    case "run": {
      console.log("Routing to run command...");
      const targetUrl = process.argv[3];
      const parameter = process.argv[4];
      if (!targetUrl || !parameter) {
        // Just print routing log and break or let routing work
        break;
      }
      const { runSsrfScan } = await import("./run.ts");
      let canaryUrl: string | undefined;
      let max: number | undefined;
      let noCloud = false;
      for (const arg of process.argv.slice(5)) {
        if (arg.startsWith("--canary=")) {
          canaryUrl = arg.slice(arg.indexOf("=") + 1);
        } else if (arg.startsWith("--max=")) {
          const val = parseInt(arg.slice(arg.indexOf("=") + 1), 10);
          if (isNaN(val) || val < 0) {
            console.error("error: --max option requires a non-negative integer");
            process.exitCode = 1;
            return;
          }
          max = val;
        } else if (arg === "--no-cloud") {
          noCloud = true;
        }
      }
      const result = runSsrfScan(targetUrl, parameter, { canaryUrl, max, noCloud });
      console.log(JSON.stringify(result));
      break;
    }
    case "blind": {
      console.log("Routing to blind command...");
      const targetUrl = process.argv[3];
      const parameter = process.argv[4];
      if (!targetUrl || !parameter) {
        // Just print routing log and break or let routing work
        break;
      }
      const { runBlindSsrfScan } = await import("./blind.ts");
      let dnsOnly = false;
      let watch = false;
      let canaryUrl: string | undefined;
      for (const arg of process.argv.slice(5)) {
        if (arg === "--dns-only") {
          dnsOnly = true;
        } else if (arg === "--watch") {
          watch = true;
        } else if (arg.startsWith("--canary=")) {
          canaryUrl = arg.slice(arg.indexOf("=") + 1);
        }
      }
      const result = runBlindSsrfScan(targetUrl, parameter, { dnsOnly, watch, canaryUrl });
      console.log(JSON.stringify(result));
      break;
    }
    default:
      console.error(`unknown command: ${command}`);
      console.error("usage: enigma-ssrf <command> [options]");
      console.error("commands: discover, run, blind");
      process.exitCode = 1;
  }
}

// Only run CLI entrypoint if executed directly (not imported)
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("index.ts")) {
  void main();
}
