/**
 * Learning Loop — explicit enactment of the competitor's decision map feedback cycle.
 *
 * @see https://labs.trace37.com/diagrams/complete-decision-map.html
 * @see https://labs.trace37.com/blog/enigma-xss-engine/ "The Knowledge Accumulation Model"
 *
 * The published decision map defines the cycle:
 *
 *   TEST → BLOCKED → LEARN → R2 (re-detect blockers) → STRATEGIES (R3+R4) →
 *     R5 (execution) → COMBINE → TEST
 *   TEST → EXHAUSTED → ENUMERATE (pivot, 80+ tags × 60+ events) → COMBINE → TEST
 *   TEST → EXECUTED → XSS FOUND (terminal)
 *
 * `MutationComposer` already holds the knowledge state; this module is the
 * first-class driver that records every cycle transition so an operator (or the
 * runtime dashboard / agent-mode CLI) can observe *why* the engine re-entered
 * R2 and which rotor advanced. Without this, the feedback loop is implicit in
 * `runner/index.ts` and cannot be reasoned about, replayed, or surfaced.
 *
 * The loop is intentionally framework-agnostic: an adapter supplies the test
 * result and学习者 receives back the next rotor phase. This keeps the module
 * decoupled from Playwright and reusable by the SSRF runner if it later adopts
 * a learning accumulation model.
 */

export type RotorPhase =
  | "r1_context"
  | "r2_blockers"
  | "r3_encoding"
  | "r4_structure"
  | "r5_execution"
  | "combine"
  | "enumerate"
  | "terminal";

export type TestOutcome = "executed" | "blocked" | "reflected" | "exhausted";

export interface LoopTransition {
  from: RotorPhase;
  to: RotorPhase;
  outcome: TestOutcome;
  payload: string;
  rationale?: string;
  ts: number;
}

export interface LearningLoopSnapshot {
  transitions: LoopTransition[];
  iterations: number;
  pivotReached: boolean;
  currentPhase: RotorPhase;
}

export interface LearningFeedback {
  successfulPayloads: string[];
  blockedPatterns: string[];
  reflectedPatterns: string[];
  rotorOutcomes: Map<string, { executed: number; blocked: number; reflected: number }>;
}

/**
 * Records the cyclic transitions of the 5-rotor decision map.
 *
 * Invariants enforced:
 * - `executed` always advances to `terminal` (blog: "XSS FOUND" terminal node).
 * - `blocked` from a rotor advances to the *next* rotor; from `combine` it
 *   loops back to `r2_blockers` per the decision map's `LEARN → R2` edge.
 * - `exhausted` from `combine` triggers `enumerate` (PIVOT branch).
 * - `enumerate` outcome feeds back into `combine` (80+ tags × 60+ events).
 */
export class LearningLoop {
  private transitions: LoopTransition[] = [];
  private currentPhase: RotorPhase = "r1_context";
  private pivotReached = false;

  get iterations(): number {
    return this.transitions.length;
  }

  snapshot(): LearningLoopSnapshot {
    return {
      transitions: [...this.transitions],
      iterations: this.transitions.length,
      pivotReached: this.pivotReached,
      currentPhase: this.currentPhase,
    };
  }

  /** Record the outcome of one TEST node and advance the rotor state. */
  record(outcome: TestOutcome, payload: string, rationale?: string): LoopTransition {
    const from = this.currentPhase;
    const to = this._nextPhase(from, outcome);
    const transition: LoopTransition = { from, to, outcome, payload, rationale, ts: Date.now() };
    this.transitions.push(transition);
    this.currentPhase = to;
    if (to === "enumerate") this.pivotReached = true;
    return transition;
  }

  /** Reset for a fresh scan (e.g. new target). Preserves no cross-scan state. */
  reset(): void {
    this.transitions = [];
    this.currentPhase = "r1_context";
    this.pivotReached = false;
  }

  /** Export NDJSON-friendly entries for the dashboard / logger. */
  toLogLines(): string[] {
    return this.transitions.map(
      (t) => JSON.stringify({ phase: t.from, to: t.to, outcome: t.outcome, payload: t.payload, rationale: t.rationale ?? null, ts: t.ts }),
    );
  }

  /** Return structured feedback for the mutation composer. */
  getFeedback(): LearningFeedback {
    const feedback: LearningFeedback = {
      successfulPayloads: [],
      blockedPatterns: [],
      reflectedPatterns: [],
      rotorOutcomes: new Map(),
    };

    for (const record of this.transitions) {
      if (record.outcome === "executed") {
        feedback.successfulPayloads.push(record.payload);
      } else if (record.outcome === "blocked") {
        feedback.blockedPatterns.push(record.payload);
      } else if (record.outcome === "reflected") {
        feedback.reflectedPatterns.push(record.payload);
      }

      const rotor = this._rotorFromRationale(record.rationale);
      const existing = feedback.rotorOutcomes.get(rotor) || { executed: 0, blocked: 0, reflected: 0 };
      if (record.outcome === "executed") existing.executed++;
      else if (record.outcome === "blocked") existing.blocked++;
      else if (record.outcome === "reflected") existing.reflected++;
      feedback.rotorOutcomes.set(rotor, existing);
    }

    return feedback;
  }

  /** Extract rotor phase name from a rationale string. */
  private _rotorFromRationale(rationale?: string): string {
    if (!rationale) return "unknown";

    // Match "[rotor: X]" format used by the runner
    const rotorMatch = rationale.match(/\[rotor:\s*(\w+)\]/);
    if (rotorMatch) {
      return rotorToPhase(rotorMatch[1]);
    }

    // Match "R#" format used in baseline testing (e.g. "R1 context baseline")
    const rMatch = rationale.match(/R(\d)/);
    if (rMatch) {
      const phaseMap: Record<string, RotorPhase> = {
        "1": "r1_context",
        "2": "r2_blockers",
        "3": "r3_encoding",
        "4": "r4_structure",
        "5": "r5_execution",
      };
      return phaseMap[rMatch[1]] || "unknown";
    }

    return "unknown";
  }

  /**
   * Decision map edges. Encoded explicitly so the mapping between code and
   * the published diagram is auditable line-by-line.
   */
  private _nextPhase(from: RotorPhase, outcome: TestOutcome): RotorPhase {
    switch (outcome) {
      case "executed":
        return "terminal"; // decision map: TEST → EXECUTED → XSS FOUND (terminal)
      case "exhausted":
        // TEST → EXHAUSTED → PIVOT/ENUMERATE → COMBINE
        if (from === "combine") return "enumerate";
        return "enumerate";
      case "blocked":
        // TEST → BLOCKED → LEARN → R2 → STRATEGIES → R5 → COMBINE → TEST
        // From R1 baseline-blocked we move to R2.
        // From R2..R5 we advance forward; from `combine` we loop back to R2.
        if (from === "r1_context") return "r2_blockers";
        if (from === "r2_blockers") return "r3_encoding";
        if (from === "r3_encoding") return "r4_structure";
        if (from === "r4_structure") return "r5_execution";
        if (from === "r5_execution") return "combine";
        if (from === "combine") return "r2_blockers"; // LEARN → R2 feedback
        if (from === "enumerate") return "combine";
        return "r2_blockers"; // safe default for unknown state
      case "reflected":
        // Reflected but not executed: blog treats as no-progress, try next strategy.
        if (from === "r1_context") return "r2_blockers";
        if (from === "r5_execution") return "combine";
        if (from === "combine") return "combine";
        return from === "terminal" ? "terminal" : "combine";
      default:
        return "terminal";
    }
  }
}

/**
 * Convenience: maps a candidate `rotor` identifier (from `MASTER-RULES.rotorWeights`)
 * into the corresponding `RotorPhase` used by the LearningLoop.  Lets the runner
 * tag each transition with the rotor that produced the candidate under test.
 */
export function rotorToPhase(rotor: string): RotorPhase {
  switch (rotor) {
    case "context": return "r1_context";
    case "blockers": return "r2_blockers";
    case "encoding": return "r3_encoding";
    case "structure": return "r4_structure";
    case "execution": return "r5_execution";
    default: return "combine";
  }
}
