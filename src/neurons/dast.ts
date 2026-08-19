import type { DastSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

/** DAST domain neuron (e.g. OWASP ZAP) — evidence from runtime exploitation. */
export function dastNeuron(signal: DastSignal): Evidence {
  if (!signal.hit) {
    // DAST only sees what it can reach and test; silence isn't strong proof.
    return { mu: 0.05, lambda: 0.15 };
  }

  if (signal.confirmed === true) {
    return { mu: 0.9, lambda: 0.05 };
  }
  if (signal.confirmed === false) {
    // A deliberate, active exploitation attempt that failed (e.g. blocked
    // by a WAF) is strong unfavorable evidence, not weak — the attack was
    // actually attempted at runtime and did not succeed.
    return { mu: 0.15, lambda: 0.7 };
  }
  // confirmed === null: passive detection (no active exploitation attempt)
  // OR unreachable target. Without passiveSeverity, we keep the original
  // pure uncertainty (mu=lambda=neutral) — unchanged behavior for the
  // synthetic scenarios, none of which set this field.
  if (!signal.passiveSeverity) {
    return { mu: 0.3, lambda: 0.3 };
  }
  const base: Record<NonNullable<DastSignal["passiveSeverity"]>, Evidence> = {
    info: { mu: 0.35, lambda: 0.2 },
    low: { mu: 0.5, lambda: 0.15 },
    medium: { mu: 0.65, lambda: 0.1 },
    high: { mu: 0.8, lambda: 0.1 },
  };
  return base[signal.passiveSeverity];
}
