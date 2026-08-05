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
 * Cluster hierarquico LPA2v: neuronios de dominio -> neuronio mestre
 * (correlacao contextual) -> persistencia temporal -> classe final.
 * Mantem estado por ativo (janela de persistencia), por isso e um objeto
 * com estado e nao uma funcao pura — precisa ser alimentado em ordem de
 * tick crescente por ativo, como faz o simulador.
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
