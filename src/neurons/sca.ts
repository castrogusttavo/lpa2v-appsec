import type { ScaSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

/** SCA domain neuron (e.g. Snyk) — evidence from a vulnerable dependency. */
export function scaNeuron(signal: ScaSignal): Evidence {
  if (!signal.hit) {
    // Neutral baseline (GC = 0), same principle as codeContextNeuron: a
    // negative baseline here was diluting genuine single-domain positives
    // from other domains in the weighted-mean consensus (see the
    // sharp/CVSS-7.0 near-miss and the Plane recall gap discussed in the
    // article).
    return { mu: 0.1, lambda: 0.1 };
  }

  let mu = (signal.cvss ?? 5) / 10;
  let lambda = 0.1;

  if (signal.exploitMaturity === "active") mu += 0.2;
  else if (signal.exploitMaturity === "poc") mu += 0.1;

  if (signal.patchAvailable === true) lambda += 0.05;

  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}
