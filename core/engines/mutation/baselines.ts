import { CONTEXT_TECHNIQUES, type ContextName } from "./context-techniques.ts";

export interface BaselineCandidate {
  context: ContextName;
  payload: string;
  description: string;
}

const BASELINES = new Map<ContextName, BaselineCandidate>(
  CONTEXT_TECHNIQUES.map((technique) => [
    technique.name as ContextName,
    {
      context: technique.name as ContextName,
      payload: technique.baseline,
      description: `Baseline payload for ${technique.name}`
    }
  ])
);

BASELINES.set("script_string", {
  context: "script_string",
  payload: "';alert(1);//",
  description: "Generic script-string breakout"
});

BASELINES.set("html_attribute", {
  context: "html_attribute",
  payload: "\" onmouseover=alert(1) x=\"",
  description: "Generic HTML attribute breakout"
});

export function getBaselineForContext(context: ContextName): BaselineCandidate {
  return BASELINES.get(context) ?? BASELINES.get("html_content")!;
}
