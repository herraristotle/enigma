import { EnigmaRunner, PlaywrightBrowserAdapter, type RunOptions } from "../../core/runner/index.ts";

async function main(): Promise<void> {
  const target = process.argv[2];
  const parameter = process.argv[3];
  
  if (!target || !parameter) {
    console.error("usage: enigma run <target> <parameter> [options]");
    console.error("  --cookie=\"session=abc123\"          Set request cookie");
    console.error("  --source=hash|path                 Specify injection source context");
    console.error("  --observe=\"https://...\"            URL to observe for stored XSS execution");
    console.error("  --form=\"key1=val1&key2=val2\"       Form data for stored XSS injection");
    console.error("  --inject-header=Referer            Inject payload into specified HTTP header");
    console.error("  --no-headless                      Run browser visibly for debugging");
    console.error("  --verbose                          Output detailed decision logging");
    process.exitCode = 1;
    return;
  }

  // Parse command line options
  const options: RunOptions = {
    verbose: process.argv.includes("--verbose")
  };

  for (const arg of process.argv.slice(4)) {
    if (arg.startsWith("--cookie=")) options.cookie = arg.split("=")[1];
    else if (arg.startsWith("--source=")) options.source = arg.split("=")[1];
    else if (arg.startsWith("--observe=")) options.observeUrl = arg.split("=")[1];
    else if (arg.startsWith("--form=")) {
      const formStr = arg.split("=").slice(1).join("=");
      options.formData = Object.fromEntries(new URLSearchParams(formStr).entries());
    }
    else if (arg.startsWith("--inject-header=")) options.injectHeader = arg.split("=")[1];
  }

  const adapter = new PlaywrightBrowserAdapter();
  try {
    await adapter.init(!process.argv.includes("--no-headless"));
  } catch (error) {
    console.error(`failed to initialize Playwright runtime: ${String(error)}`);
    process.exitCode = 1;
    return;
  }

  if (options.verbose) {
    console.log(`[+] Starting Enigma autonomous scan for ${target}`);
    console.log(`[+] Parameter/Injection point: ${parameter}`);
    if (options.cookie) console.log(`[+] Cookie attached`);
    if (options.source) console.log(`[+] Source mechanism: ${options.source}`);
    if (options.observeUrl) console.log(`[+] Stored XSS observation URL: ${options.observeUrl}`);
    if (options.injectHeader) console.log(`[+] Header injection: ${options.injectHeader}`);
  }

  const runner = new EnigmaRunner(adapter, options);
  const result = await runner.run(target, parameter);
  await adapter.close?.();
  
  if (options.verbose) {
    console.log("\\n" + "=".repeat(40));
    console.log(`Scan Complete for ${target}`);
    console.log(`Detected Context: ${result.context}`);
    console.log("=".repeat(40));
  }

  console.log(JSON.stringify(result, null, 2));

  if (result.success) {
    if (options.verbose) {
      console.log("\\n[!] XSS Payload found!");
      const winPayload = result.attempts[result.attempts.length - 1].payload;
      console.log(`[!] Payload: ${winPayload}`);
    }
    process.exitCode = 0;
  } else {
    if (options.verbose) console.log("\\n[-] Exhausted search space without finding execution.");
    process.exitCode = 1;
  }
}

void main();
