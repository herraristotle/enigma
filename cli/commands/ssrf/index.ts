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
      let execute = false;
      let timeout: number | undefined;
      let verbose = false;
      let slackWebhook: string | undefined;
      let testHeaders = false;
      let internalTarget: string | undefined;
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
        } else if (arg === "--execute") {
          execute = true;
        } else if (arg.startsWith("--timeout=")) {
          timeout = parseInt(arg.slice(arg.indexOf("=") + 1), 10);
        } else if (arg === "--verbose") {
          verbose = true;
        } else if (arg.startsWith("--slack-webhook=")) {
          slackWebhook = arg.slice(arg.indexOf("=") + 1);
        } else if (arg === "--test-headers") {
          testHeaders = true;
        } else if (arg.startsWith("--target=")) {
          internalTarget = arg.slice(arg.indexOf("=") + 1);
        }
      }
      const scanOptions = { canaryUrl, max, noCloud, timeout, verbose, slackWebhook, testHeaders, targetUrl: internalTarget, execute };
      const plan = runSsrfScan(targetUrl, parameter, scanOptions);
      if (execute) {
        const { executeSsrfPlan } = await import("../../../core/engines/ssrf/executor.ts");
        const outcome = await executeSsrfPlan(targetUrl, parameter, plan, {
          timeoutMs: timeout ?? 5000,
          maxAttempts: max,
          slackWebhook,
          verbose
        });
        console.log(JSON.stringify(outcome, null, 2));
        process.exitCode = outcome.confirmed > 0 ? 0 : 1;
      } else {
        console.log(JSON.stringify(plan));
      }
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
      const { runBlindSsrfScan, watchForCallbacks } = await import("./blind.ts");
      let dnsOnly = false;
      let watch = false;
      let canaryUrl: string | undefined;
      let slackWebhook: string | undefined;
      let watchTimeoutMs = 60_000;
      for (const arg of process.argv.slice(5)) {
        if (arg === "--dns-only") {
          dnsOnly = true;
        } else if (arg === "--watch") {
          watch = true;
        } else if (arg.startsWith("--canary=")) {
          canaryUrl = arg.slice(arg.indexOf("=") + 1);
        } else if (arg.startsWith("--slack-webhook=")) {
          slackWebhook = arg.slice(arg.indexOf("=") + 1);
        } else if (arg.startsWith("--watch-timeout=")) {
          const parsed = Number.parseInt(arg.slice(arg.indexOf("=") + 1), 10);
          if (Number.isFinite(parsed) && parsed >= 0) watchTimeoutMs = parsed;
        }
      }
      const result = runBlindSsrfScan(targetUrl, parameter, { dnsOnly, watch, canaryUrl });
      console.log(JSON.stringify(result));
      if (watch) {
        await watchForCallbacks(canaryUrl || "http://localhost:8080/c/TOKEN", {
          targetUrl,
          parameter,
          slackWebhook,
          timeoutMs: watchTimeoutMs
        });
      }
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
