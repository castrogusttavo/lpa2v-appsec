// Core of two-valued paraconsistent annotated logic (LPA2v).
//
// For a proposition P ("this finding is a real vulnerability"), a
// paraconsistent neuron estimates:
//   mu     (degree of FAVORABLE evidence for P)     in [0, 1]
//   lambda (degree of UNFAVORABLE evidence for P)   in [0, 1]
//
// From these:
//   GC  = mu - lambda        certainty degree      in [-1, 1]
//   GCT = mu + lambda - 1    contradiction degree   in [-1, 1]
//
// Theoretical grounding: da Costa (1974), Abe (2015).
//
// The final classification uses 5 classes (normal/atencao/degradacao/
// critico/inconsistente) for AppSec finding triage (SAST/SCA/DAST). The
// class names stay in Portuguese: they are the vocabulary used throughout
// this project's article and figures.

import type { ParaClass } from "./types.js";

export interface Evidence {
  mu: number;
  lambda: number;
}

export interface ParaconsistentThresholds {
  /** GCT above which the state becomes "inconsistente", regardless of GC. */
  contradiction: number;
  /** Minimum GC for each ascending severity level. */
  attention: number;
  degradation: number;
  critical: number;
}

export const DEFAULT_THRESHOLDS: ParaconsistentThresholds = {
  contradiction: 0.5,
  attention: 0.18,
  degradation: 0.35,
  critical: 0.6,
};

export function clamp01(x: number): number {
  return Math.min(1, Math.max(0, x));
}

export function certaintyDegree(e: Evidence): number {
  return e.mu - e.lambda;
}

export function contradictionDegree(e: Evidence): number {
  return e.mu + e.lambda - 1;
}

/**
 * Combines evidence from multiple neurons (domains) into aggregated
 * evidence, via weighted mean of mu and of lambda — this is how the master
 * neuron of the hierarchical cluster aggregates the specialized neurons.
 */
export function combineEvidence(
  inputs: ReadonlyArray<{ evidence: Evidence; weight: number }>,
): Evidence {
  const totalWeight = inputs.reduce((sum, i) => sum + i.weight, 0);
  if (totalWeight <= 0) return { mu: 0, lambda: 0 };
  const mu = inputs.reduce((sum, i) => sum + i.evidence.mu * i.weight, 0) / totalWeight;
  const lambda = inputs.reduce((sum, i) => sum + i.evidence.lambda * i.weight, 0) / totalWeight;
  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}

function rankByCertainty(gc: number, thresholds: ParaconsistentThresholds): ParaClass {
  if (gc >= thresholds.critical) return "critico";
  if (gc >= thresholds.degradation) return "degradacao";
  if (gc >= thresholds.attention) return "atencao";
  return "normal";
}

export function classify(
  e: Evidence,
  thresholds: ParaconsistentThresholds = DEFAULT_THRESHOLDS,
): ParaClass {
  if (contradictionDegree(e) >= thresholds.contradiction) return "inconsistente";
  return rankByCertainty(certaintyDegree(e), thresholds);
}

/**
 * Hierarchical cluster classification: uses TWO evidence signals.
 *
 * `aggregated` (weighted mean of mu and lambda across domain neurons)
 * measures CONSENSUS — how much the domains agree there is real risk —
 * and drives the normal/atencao/degradacao/critico ranking.
 *
 * `contradiction` (the LARGEST mu across domains vs. the LARGEST lambda
 * across domains, possibly from different domains) measures CONFLICT —
 * whether some domain strongly asserts risk while another strongly refutes
 * it.
 *
 * The weighted mean alone dilutes real contradictions: if SAST says
 * "strongly favorable" (high mu) and DAST says "strongly unfavorable"
 * (high lambda), the mean of mu and the mean of lambda both drift toward
 * the center and the resulting GCT stays low — the opposite of what
 * paraconsistent logic should capture (preserving both strong pieces of
 * evidence, not averaging them away). That's why the contradiction test
 * uses the extremes across domains, not the mean.
 */
export function classifyCluster(
  aggregated: Evidence,
  contradiction: Evidence,
  thresholds: ParaconsistentThresholds = DEFAULT_THRESHOLDS,
): ParaClass {
  if (contradictionDegree(contradiction) >= thresholds.contradiction) return "inconsistente";
  return rankByCertainty(certaintyDegree(aggregated), thresholds);
}
