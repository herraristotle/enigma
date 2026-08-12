export interface DecisionLogEntry {
  phase: string;
  action: string;
  detail: string;
  ts: number;
}

export class DecisionTreeLogger {
  private readonly entries: DecisionLogEntry[] = [];

  record(phase: string, action: string, detail: string): void {
    this.entries.push({ phase, action, detail, ts: Date.now() });
  }

  export(): DecisionLogEntry[] {
    return [...this.entries];
  }
}

