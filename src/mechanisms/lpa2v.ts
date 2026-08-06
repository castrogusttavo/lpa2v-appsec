import type { Asset, RawSignal, ParaClass } from "../core/types.js";
import { Lpa2vCluster, type Lpa2vClusterOptions } from "../cluster/lpa2vCluster.js";

/** Builds a stateful LPA2v classifier (per-asset persistence). */
export function makeLpa2vMechanism(options: Lpa2vClusterOptions = {}) {
  const cluster = new Lpa2vCluster(options);
  return (assetId: string, signal: RawSignal, asset: Asset): ParaClass =>
    cluster.classify(assetId, signal, asset);
}
