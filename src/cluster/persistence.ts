import type { ParaClass } from "../core/types.js";

// Temporal persistence: each "tick" here represents one scan cycle (not a
// minute), and the cluster only lets a severity climb to degradacao/critico
// once it's been sustained for `windowSize` consecutive ticks. This has two
// intentional effects, both visible in the simulated scenarios:
//   1. Prevents an isolated, unstable finding (e.g. a flaky scanner) from
//      firing a critical alert outright.
//   2. Creates a "warm-up" delay: severity only escalates once the trend is
//      confirmed, which produces an anticipation effect (the certainty
//      degree rises visibly before the final class catches up).

const RANK: Record<Exclude<ParaClass, "inconsistente">, number> = {
  normal: 0,
  atencao: 1,
  degradacao: 2,
  critico: 3,
};

const RANK_TO_CLASS: Exclude<ParaClass, "inconsistente">[] = [
  "normal",
  "atencao",
  "degradacao",
  "critico",
];

export class PersistenceTracker {
  private readonly windows = new Map<string, number[]>();

  constructor(private readonly windowSize: number = 3) {}

  apply(assetId: string, rawClass: ParaClass): ParaClass {
    if (rawClass === "inconsistente") {
      // Contradiction is itself the informative result — no reason to
      // delay reporting it, and the tick doesn't enter the severity window.
      return "inconsistente";
    }

    const rank = RANK[rawClass];
    const hist = this.windows.get(assetId) ?? [];
    hist.push(rank);
    if (hist.length > this.windowSize) hist.shift();
    this.windows.set(assetId, hist);

    const warmingUp = hist.length < this.windowSize;
    const sustainedRank = warmingUp
      ? Math.min(rank, RANK.atencao)
      : Math.min(...hist);

    const finalClass = RANK_TO_CLASS[sustainedRank];
    if (finalClass === undefined) {
      throw new Error(`Invalid rank: ${sustainedRank}`);
    }
    return finalClass;
  }

  reset(): void {
    this.windows.clear();
  }
}
