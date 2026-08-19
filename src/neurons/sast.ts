import type { SastSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

const SEVERITY_BASE: Record<SastSignal["severity"], number> = {
  info: 0.15,
  low: 0.3,
  medium: 0.5,
  high: 0.72,
  critical: 0.88,
};

const CONFIDENCE_SCALE: Record<SastSignal["confidence"], number> = {
  low: 0.6,
  medium: 0.85,
  high: 1.0,
};

/** SAST domain neuron (e.g. Semgrep) — evidence from a static match. */
export function sastNeuron(signal: SastSignal): Evidence {
  if (!signal.hit) {
    // No match is not strong proof of safety: SAST has limited visibility
    // (it doesn't see dependencies or runtime behavior).
    return { mu: 0.03, lambda: 0.15 };
  }

  let mu = SEVERITY_BASE[signal.severity] * CONFIDENCE_SCALE[signal.confidence];
  let lambda = 0.05;

  if (signal.reachable === false) {
    // Static match in code that's likely dead/unreachable at runtime.
    mu *= 0.4;
    lambda += 0.45;
  } else if (signal.reachable === true) {
    mu += 0.1;
  }
  // reachable === null (unknown): no adjustment, pure uncertainty.

  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}
