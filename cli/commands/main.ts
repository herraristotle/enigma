#!/usr/bin/env node
// Single entrypoint: `enigma <run|ssrf|payloads>`.
//
// The subcommand modules export `main()` and keep an
// `import.meta.url === file://${process.argv[1]}` guard for direct execution,
// so this router is the only caller when the CLI is invoked normally.
//
// Imports are static on purpose: a dynamic `import("./run.ts")` cannot be
// resolved from the compiled output (the specifier points at a file that no
// longer exists there), and static imports make the module graph visible to
// `tsc`, so a missing command fails the build instead of the run.

import { main as runMain } from "./run.ts";
import { main as payloadsMain } from "./payloads.ts";
import { main as ssrfRunMain } from "./ssrf/run.ts";
import { main as ssrfDiscoverMain } from "./ssrf/discover.ts";
import { main as ssrfBlindMain } from "./ssrf/blind.ts";

async function main(): Promise<void> {
  const command = process.argv[2];

  // Each subcommand module reads its own positionals from process.argv, so the
  // router tokens have to be removed before handing over — otherwise `run` sees
  // "run" as the target. Direct execution of a subcommand module is unaffected.
  const strip = (count: number): void => {
    process.argv = [process.argv[0], process.argv[1], ...process.argv.slice(2 + count)];
  };

  switch (command) {
    case "run": {
      strip(1);
      await runMain();
      break;
    }
    case "ssrf": {
      const ssrfCommand = process.argv[3];
      if (!ssrfCommand) {
        console.error("usage: enigma ssrf <run|discover|blind> [options]");
        process.exitCode = 1;
        return;
      }
      strip(2);
      if (ssrfCommand === "discover") {
        await ssrfDiscoverMain();
      } else if (ssrfCommand === "blind") {
        await ssrfBlindMain();
      } else if (ssrfCommand === "run") {
        await ssrfRunMain();
      } else {
        console.error(`Unknown ssrf command: ${ssrfCommand}`);
        console.error("commands: run, discover, blind");
        process.exitCode = 1;
      }
      break;
    }
    case "payloads": {
      strip(1);
      await payloadsMain();
      break;
    }
    default:
      console.error("usage: enigma <command> [options]");
      console.error("commands:");
      console.error("  run <target> <parameter> [options]     - Autonomous XSS mutation scan");
      console.error("  ssrf run <target> <parameter> [options] - Autonomous SSRF scan");
      console.error("  ssrf discover <target> [options]      - SSRF surface discovery");
      console.error("  ssrf blind <target> <parameter> [options] - Blind SSRF scan");
      console.error("  payloads --context=... [options]      - Batch payload generation");
      process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
