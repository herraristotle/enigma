import { MutationComposer } from "../../core/engines/mutation/composer.ts";

/**
 * Batch payload generation for machine consumers (e.g. the Mastermind-Ai
 * Python bridge). Prints deterministic JSON candidates for the requested
 * contexts using the MutationComposer's cascade ordering.
 *
 * Usage:
 *   node --experimental-strip-types cli/commands/payloads.ts \
 *     --context=html --context=url --waf=cloudflare --seed=1337 --max=12
 */

const CONTEXT_ALIASES: Record<string, string> = {
  html: "html_content",
  html_content: "html_content",
  attribute: "html_attribute",
  html_attribute: "html_attribute",
  javascript: "script_string",
  script_string: "script_string",
  url: "href_attribute",
  href_attribute: "href_attribute",
  css: "style_attribute",
  style_attribute: "style_attribute"
};

function flagValue(name: string): string | undefined {
  const prefix = `--${name}=`;
  const arg = process.argv.find((value) => value.startsWith(prefix));
  return arg ? arg.slice(prefix.length) : undefined;
}

function flagValues(name: string): string[] {
  const prefix = `--${name}=`;
  return process.argv
    .filter((value) => value.startsWith(prefix))
    .map((value) => value.slice(prefix.length))
    .filter(Boolean);
}

async function main(): Promise<void> {
  const requested = flagValues("context");
  const contexts = (requested.length > 0 ? requested : ["html"])
    .map((value) => CONTEXT_ALIASES[value.toLowerCase()])
    .filter((value): value is string => Boolean(value));
  if (contexts.length === 0) {
    console.error(`Unknown context. Valid values: ${Object.keys(CONTEXT_ALIASES).join(", ")}`);
    process.exit(1);
  }
  const waf = flagValue("waf") ?? "";
  const seed = flagValue("seed") ?? "";
  const max = Math.max(1, Number.parseInt(flagValue("max") ?? "12", 10) || 12);

  const seen = new Set<string>();
  const candidates: Array<Record<string, string>> = [];
  for (const context of contexts) {
    const composer = new MutationComposer(context);
    for (const candidate of composer.nextCandidates()) {
      if (seen.has(candidate.payload)) continue;
      seen.add(candidate.payload);
      candidates.push({
        payload: candidate.payload,
        context,
        technique: candidate.family || candidate.rotor,
        strategy: candidate.rotor,
        rationale: candidate.rationale
      });
      if (candidates.length >= max) break;
    }
    if (candidates.length >= max) break;
  }

  console.log(
    JSON.stringify({ contexts, waf, seed, count: candidates.length, candidates }, null, 2)
  );
}

void main();
