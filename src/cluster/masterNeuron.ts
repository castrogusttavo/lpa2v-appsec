import type { Asset, RawSignal } from "../core/types.js";
import { combineEvidence, type Evidence } from "../core/paraconsistent.js";
import { sastNeuron } from "../neurons/sast.js";
import { scaNeuron } from "../neurons/sca.js";
import { dastNeuron } from "../neurons/dast.js";
import { codeContextNeuron } from "../neurons/codeContext.js";
import { opContextNeuron } from "../neurons/opContext.js";

/**
 * Domain neuron weights in the master neuron's aggregation. SAST/SCA/DAST
 * are the primary detectors. Code context and operational context get a
 * higher weight than a single detector because, when they fire, they
 * reflect near-factual metadata (this is a test, this is an authorized
 * maintenance window) rather than a probabilistic match — they need to be
 * able to override a single primary detector's verdict, e.g. an
 * authorized maintenance window explaining away an otherwise-alarming
 * technical signal.
 */
export const DEFAULT_WEIGHTS = {
  sast: 1.2,
  sca: 1.3,
  dast: 1.3,
  codeContext: 1.3,
  opContext: 1.3,
};

export interface DomainBreakdown {
  sast: Evidence;
  sca: Evidence;
  dast: Evidence;
  codeContext: Evidence;
  opContext: Evidence;
}

export function evaluateDomainNeurons(signal: RawSignal, asset: Asset): DomainBreakdown {
  return {
    sast: sastNeuron(signal.sast),
    sca: scaNeuron(signal.sca),
    dast: dastNeuron(signal.dast),
    codeContext: codeContextNeuron(signal.codeContext),
    opContext: opContextNeuron(signal.opContext, asset),
  };
}

/** Master neuron: aggregates domain-neuron evidence (contextual correlation). */
export function masterNeuron(
  breakdown: DomainBreakdown,
  weights: typeof DEFAULT_WEIGHTS = DEFAULT_WEIGHTS,
): Evidence {
  return combineEvidence([
    { evidence: breakdown.sast, weight: weights.sast },
    { evidence: breakdown.sca, weight: weights.sca },
    { evidence: breakdown.dast, weight: weights.dast },
    { evidence: breakdown.codeContext, weight: weights.codeContext },
    { evidence: breakdown.opContext, weight: weights.opContext },
  ]);
}

/**
 * Contradiction signal: the largest mu across the PRIMARY DETECTORS
 * (SAST/SCA/DAST) vs. the largest lambda across them (may come from
 * different detectors). Preserves the case where one detector strongly
 * asserts risk and another strongly refutes it, instead of letting the
 * mean erase both extremes — see the note on `classifyCluster`.
 *
 * Code/operational context is deliberately left out of this calculation:
 * they aren't "one more opinion on whether a vulnerability exists," they
 * are explanatory metadata (why the detector fired) — when context
 * explains a finding (e.g. an authorized maintenance window), the correct
 * outcome is to suppress the severity, not to declare an inconsistent
 * state that asks for human review.
 */
export function contradictionSignal(breakdown: DomainBreakdown): Evidence {
  const primary = [breakdown.sast, breakdown.sca, breakdown.dast];
  return {
    mu: Math.max(...primary.map((v) => v.mu)),
    lambda: Math.max(...primary.map((v) => v.lambda)),
  };
}

/**
 * Highest certainty degree (GC = mu - lambda) reached by any ONE primary
 * detector on its own — not mu and lambda maxed independently like
 * `contradictionSignal` (which can mix extremes from different domains).
 * Used to let a single genuinely extreme finding (e.g. a confirmed,
 * actively exploited, maximum-severity CVE seen only by SCA) escape the
 * weighted-mean consensus's structural cap — see `primaryOverride` in
 * `ParaconsistentThresholds`.
 */
export function primaryDomainMaxCertainty(breakdown: DomainBreakdown): number {
  const primary = [breakdown.sast, breakdown.sca, breakdown.dast];
  return Math.max(...primary.map((v) => v.mu - v.lambda));
}

/**
 * True when code/operational context show no active SUPPRESSION signal —
 * lambda sitting at its neutral baseline (~0.1) rather than boosted by a
 * flag (test fixture, maintenance window, deprecated module, internal-only
 * network). Deliberately checks lambda only, not mu: opContext's mu bump
 * for public-facing-without-auth is an amplification, not a suppression,
 * and shouldn't block the override — only a domain actively explaining the
 * finding away should. The `primaryOverride` escape hatch only applies
 * when this holds — otherwise a single strong technical signal could
 * bypass context that's correctly suppressing it (e.g. a test-fixture
 * finding).
 */
export function isContextNeutral(breakdown: DomainBreakdown): boolean {
  const NEUTRAL_LAMBDA = 0.15; // baseline lambda is 0.1; a little slack for float noise
  return breakdown.codeContext.lambda <= NEUTRAL_LAMBDA && breakdown.opContext.lambda <= NEUTRAL_LAMBDA;
}
