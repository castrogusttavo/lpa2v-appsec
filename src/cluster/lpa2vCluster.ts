import type { Asset, RawSignal } from "../core/types.js";
import { classifyCluster, type ParaconsistentThresholds, DEFAULT_THRESHOLDS } from "../core/paraconsistent.js";
import { evaluateDomainNeurons, masterNeuron, contradictionSignal, DEFAULT_WEIGHTS } from "./masterNeuron.js";
import { PersistenceTracker } from "./persistence.js";
import type { ParaClass } from "../core/types.js";

export interface Lpa2vClusterOptions {
  thresholds?: ParaconsistentThresholds;
  weights?: typeof DEFAULT_WEIGHTS;
  persistenceWindow?: number;
}

/**
 * Hierarchical LPA2v cluster: domain neurons -> master neuron (contextual
 * correlation) -> temporal persistence -> final class. Keeps per-asset
 * state (the persistence window), so it's a stateful object rather than a
 * pure function — it must be fed in increasing-tick order per asset, which
 * is what the simulator does.
 */
export class Lpa2vCluster {
  private readonly tracker: PersistenceTracker;
  private readonly thresholds: ParaconsistentThresholds;
  private readonly weights: typeof DEFAULT_WEIGHTS;

  constructor(options: Lpa2vClusterOptions = {}) {
    this.thresholds = options.thresholds ?? DEFAULT_THRESHOLDS;
    this.weights = options.weights ?? DEFAULT_WEIGHTS;
    this.tracker = new PersistenceTracker(options.persistenceWindow ?? 3);
  }

  classify(assetId: string, signal: RawSignal, asset: Asset): ParaClass {
    const breakdown = evaluateDomainNeurons(signal, asset);
    const aggregated = masterNeuron(breakdown, this.weights);
    const contradiction = contradictionSignal(breakdown);
    const rawClass = classifyCluster(aggregated, contradiction, this.thresholds);
    return this.tracker.apply(assetId, rawClass);
  }
}
