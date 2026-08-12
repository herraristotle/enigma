# SSRF Run and Blind CLI Commands Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement CLI commands `run` and `blind` for SSRF scanning, which generate and filter payloads with structured JSON outputs.

**Architecture:** Route commands from `cli/commands/ssrf/index.ts` to `cli/commands/ssrf/run.ts` and `cli/commands/ssrf/blind.ts`. Parse arguments and options (`--canary`, `--max`, `--no-cloud`, `--dns-only`, `--watch`), generate plans using existing core engine logic, filter based on options, and output the result as a structured JSON array.

**Tech Stack:** Node.js (v20+ CLI), TypeScript, node:test runner.

---

### Task 1: Write failing test file for SSRF run and blind commands

**Files:**
- Create: `C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\tests\ssrf-run-blind.test.ts`

**Step 1: Write the failing test**
Create a test file that executes the CLI tool via child_process/execSync and asserts on:
- Command parsing for `--canary`, `--max`, `--no-cloud`, `--dns-only`, `--watch`.
- Proper JSON output for run command (JSON array of payload targets).
- Proper JSON output for blind command (JSON array of OOB callback payloads).
- Max payload count limits the number of generated payloads in output.
- `--no-cloud` skips generating cloud metadata endpoints.
- CLI execution matches the documented commands.

**Step 2: Run test to verify it fails**
Run: `node --experimental-strip-types --test C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\tests\ssrf-run-blind.test.ts`
Expected: Fail because commands are not implemented / routed correctly.

**Step 3: Commit**
```bash
git add C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\tests\ssrf-run-blind.test.ts
git commit -m "test: add ssrf-run-blind tests"
```

---

### Task 2: Implement run command logic

**Files:**
- Create: `C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\cli\commands\ssrf\run.ts`

**Step 1: Write implementation**
Create `run.ts` with `runSsrfScan(targetUrl: string, parameter: string, options: { canaryUrl?: string; max?: number; noCloud?: boolean })` that:
- Calls `generateSsrfPayloadPlan`.
- Filters out cloud metadata if `noCloud` is true.
- Limits results to `max` if specified.
- Returns the list of payloads.
Include a `main` CLI runner wrapper that parses process.argv if called directly, printing the JSON array output.

**Step 2: Commit**
```bash
git add C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\cli\commands\ssrf\run.ts
git commit -m "feat: implement run Ssrf CLI command"
```

---

### Task 3: Implement blind command logic

**Files:**
- Create: `C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\cli\commands\ssrf\blind.ts`

**Step 1: Write implementation**
Create `blind.ts` with `runBlindSsrfScan(targetUrl: string, parameter: string, options: { dnsOnly?: boolean; watch?: boolean; canaryUrl?: string })` that:
- Uses `CanaryRegistry` to register and retrieve OOB callback payloads.
- If `dnsOnly` is true, returns only the DNS-only callback payload.
- Otherwise, returns the appropriate array of OOB callbacks.
- If `watch` is enabled, simulates/sets up OOB callback monitoring.
Include CLI command/parsing wrapper.

**Step 2: Commit**
```bash
git add C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\cli\commands\ssrf\blind.ts
git commit -m "feat: implement blind Ssrf CLI command"
```

---

### Task 4: Route commands in cli/commands/ssrf/index.ts

**Files:**
- Modify: `C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\cli\commands\ssrf\index.ts`

**Step 1: Write routing logic**
Update the router in `index.ts` to parse:
- `--canary`, `--max`, `--no-cloud` for the `run` command, then call `runSsrfScan` and output JSON.
- `--dns-only`, `--watch`, `--canary` (or generate/default one) for the `blind` command, then call `runBlindSsrfScan` and output JSON.

**Step 2: Run test to verify it passes**
Run: `node --experimental-strip-types --test C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\tests\ssrf-run-blind.test.ts`
Expected: PASS

**Step 3: Commit**
```bash
git add C:\Users\sysadmin\Documents\workspace\bot\Mastermind-Ai\enigma\cli\commands\ssrf\index.ts
git commit -m "feat: route run and blind commands in cli entrypoint"
```
