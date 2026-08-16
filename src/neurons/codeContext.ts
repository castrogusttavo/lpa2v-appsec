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

  // 0.82, not 0.75: with sast/sca/dast "not hit" now neutral (GC=0) instead
  // of leaning safe, this suppression alone has to carry the test-fixture
  // scenario's two simultaneous strong primary-detector positives (SAST +
  // SCA) below the attention threshold — the small safety-leaning margin
  // those domains used to contribute is gone.
  if (signal.inTestOrFixture) lambda += 0.82;
  if (signal.suppressedPreviously) lambda += 0.4;
  if (signal.deprecatedModule) lambda += 0.3;

  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}
