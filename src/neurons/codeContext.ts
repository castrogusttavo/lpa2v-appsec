import type { CodeContextSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

/**
 * Code-context neuron — doesn't detect vulnerabilities on its own, but
 * supplies evidence (favorable or unfavorable) on whether a finding from
 * the primary detectors (SAST/SCA/DAST) reflects real risk.
 */
export function codeContextNeuron(signal: CodeContextSignal): Evidence {
  // Neutral baseline (GC = 0): with no flag set, this neuron has no
  // opinion and shouldn't pull the cluster's mean in either direction.
  let mu = 0.1;
  let lambda = 0.1;

  if (signal.inTestOrFixture) lambda += 0.75;
  if (signal.suppressedPreviously) lambda += 0.4;
  if (signal.deprecatedModule) lambda += 0.3;

  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}
