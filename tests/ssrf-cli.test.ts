import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

test("package exposes separate enigma-ssrf binary", () => {
  const packageJsonPath = path.resolve(import.meta.dirname, "../package.json");
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
  
  assert.ok(packageJson.bin, "package.json missing 'bin' field");
  assert.strictEqual(
    packageJson.bin["enigma-ssrf"],
    "./cli/commands/ssrf/index.ts",
    "enigma-ssrf binary mapping incorrect"
  );
});

test("CLI router routes discover command", () => {
  const scriptPath = path.resolve(import.meta.dirname, "../cli/commands/ssrf/index.ts");
  const output = execSync(`node --experimental-strip-types "${scriptPath}" discover --help`, { encoding: "utf8" });
  assert.ok(output.includes("discover"), "Output should contain discover routing message");
});

test("CLI router routes run command", () => {
  const scriptPath = path.resolve(import.meta.dirname, "../cli/commands/ssrf/index.ts");
  const output = execSync(`node --experimental-strip-types "${scriptPath}" run --help`, { encoding: "utf8" });
  assert.ok(output.includes("run"), "Output should contain run routing message");
});

test("CLI router routes blind command", () => {
  const scriptPath = path.resolve(import.meta.dirname, "../cli/commands/ssrf/index.ts");
  const output = execSync(`node --experimental-strip-types "${scriptPath}" blind --help`, { encoding: "utf8" });
  assert.ok(output.includes("blind"), "Output should contain blind routing message");
});

test("CLI router prints usage on missing argument", () => {
  const scriptPath = path.resolve(import.meta.dirname, "../cli/commands/ssrf/index.ts");
  let error: any = null;
  let stdout = "";
  let stderr = "";
  try {
    execSync(`node --experimental-strip-types "${scriptPath}"`, { encoding: "utf8", stdio: "pipe" });
  } catch (e: any) {
    error = e;
    stdout = e.stdout || "";
    stderr = e.stderr || "";
  }
  assert.ok(error, "Execution should fail");
  assert.strictEqual(error.status, 1, "Exit code should be 1");
  assert.ok(stderr.includes("usage: enigma-ssrf <command> [options]"), "Stderr should contain usage");
});

test("CLI router prints error on unknown command", () => {
  const scriptPath = path.resolve(import.meta.dirname, "../cli/commands/ssrf/index.ts");
  let error: any = null;
  let stdout = "";
  let stderr = "";
  try {
    execSync(`node --experimental-strip-types "${scriptPath}" invalidcmd`, { encoding: "utf8", stdio: "pipe" });
  } catch (e: any) {
    error = e;
    stdout = e.stdout || "";
    stderr = e.stderr || "";
  }
  assert.ok(error, "Execution should fail");
  assert.strictEqual(error.status, 1, "Exit code should be 1");
  assert.ok(stderr.includes("unknown command: invalidcmd"), "Stderr should contain unknown command");
});
