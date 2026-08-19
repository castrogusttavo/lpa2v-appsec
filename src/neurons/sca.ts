import type { ScaSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

/** SCA domain neuron (e.g. Snyk) — evidence from a vulnerable dependency. */
export function scaNeuron(signal: ScaSignal): Evidence {
  if (!signal.hit) {
    // SCA has near-complete visibility into declared dependencies, so no
    // match is relatively more reliable evidence of safety than no match
    // from SAST/DAST.
    return { mu: 0.03, lambda: 0.2 };
  }

  let mu = (signal.cvss ?? 5) / 10;
  let lambda = 0.1;

  if (signal.exploitMaturity === "active") mu += 0.2;
  else if (signal.exploitMaturity === "poc") mu += 0.1;

  if (signal.patchAvailable === true) lambda += 0.05;

  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}
