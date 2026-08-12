import { BLOCKER_PROBES, type ComponentObservation } from "./mutation/blockers.ts";

export interface TriggerProbeAdapter {
  probe(value: string): Promise<{ blocked: boolean; reflected: boolean; successful: boolean }>;
}

export async function runBinarySearch(payload: string, adapter: TriggerProbeAdapter): Promise<ComponentObservation[]> {
  const observations: ComponentObservation[] = [];
  for (const family of BLOCKER_PROBES) {
    for (const value of family.values.filter((item) => payload.includes(item) || family.family === "tag")) {
      const result = await adapter.probe(value);
      observations.push({
        family: family.family,
        value,
        blocked: result.blocked,
        successful: result.successful,
        reflected: result.reflected
      });
    }
  }
  return observations;
}
