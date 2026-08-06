import type { Asset, OpContextSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

/**
 * Operational-context neuron — deployment/runtime facts that explain a
 * finding rather than confirm it: maintenance/pentest windows, low-traffic
 * environments, public exposure, and presence of auth middleware.
 */
export function opContextNeuron(signal: OpContextSignal, asset: Asset): Evidence {
  let mu = 0.1;
  let lambda = 0.1;

  if (signal.maintenanceOrPentestWindow) lambda += 0.5;
  if (signal.lowTrafficStaging) lambda += 0.25;
  if (signal.internalOnlyNetwork) lambda += 0.3;

  if (asset.publicFacing && !asset.hasAuthMiddleware) mu += 0.35;
  else if (asset.publicFacing && asset.hasAuthMiddleware) mu += 0.1;

  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}
