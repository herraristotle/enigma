#!/usr/bin/env -S node --experimental-strip-types

async function main(): Promise<void> {
  const command = process.argv[2];

  if (!command) {
    console.error("usage: enigma <command> [options]");
    console.error("commands:");
    console.error("  run <target> <parameter> [options]     - Autonomous XSS mutation scan");
    console.error("  ssrf run <target> <parameter> [options] - Autonomous SSRF scan");
    console.error("  ssrf discover <target> [options]      - SSRF surface discovery");
    console.error("  ssrf blind <target> <parameter> [options] - Blind SSRF scan");
    console.error("  payloads --context=... [options]      - Batch payload generation");
    process.exitCode = 1;
    return;
  }

  switch (command) {
    case "run": {
      const { run } = await import("./run.ts");
      await run();
      break;
    }
    case "ssrf": {
      const ssrfCommand = process.argv[3];
      if (!ssrfCommand) {
        console.error("usage: enigma ssrf <run|discover|blind> [options]");
        process.exitCode = 1;
        return;
      }
      process.argv = [process.argv[0], process.argv[1], ssrfCommand, ...process.argv.slice(4)];
      if (ssrfCommand === "discover") {
        const { main: discoverMain } = await import("./ssrf/discover.ts");
        await discoverMain();
      } else if (ssrfCommand === "blind") {
        const { main: blindMain } = await import("./ssrf/blind.ts");
        await blindMain();
      } else if (ssrfCommand === "run") {
        const { main: ssrfRunMain } = await import("./ssrf/run.ts");
        await ssrfRunMain();
      } else {
        console.error(`Unknown ssrf command: ${ssrfCommand}`);
        console.error("commands: run, discover, blind");
        process.exitCode = 1;
      }
      break;
    }
    case "payloads": {
      const { main: payloadsMain } = await import("./payloads.ts");
      await payloadsMain();
      break;
    }
    default:
      console.error(`Unknown command: ${command}`);
      console.error("commands: run, ssrf, payloads");
      process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
