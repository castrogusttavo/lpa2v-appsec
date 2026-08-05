import type { ClassifiedEvent } from "../core/types.js";

export interface ConfusionMetrics {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  inconsistent: number;
  inconsistentButActuallyVulnerable: number;
  alerts: number;
  totalEscalations: number;
  precision: number;
  recall: number;
  f1: number;
}

/**
 * "Alerta" = classe diferente de normal e diferente de inconsistente.
 * Inconsistente e tratado como uma terceira gaveta (revisao humana), nao
 * como TP/FP — igual ao artigo original, que reporta "tratamento de
 * estados inconsistentes" como metrica separada de FP/FN.
 */
export function computeConfusion(events: ClassifiedEvent[]): ConfusionMetrics {
  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;
  let inconsistent = 0;
  let inconsistentButActuallyVulnerable = 0;

  for (const event of events) {
    if (event.class === "inconsistente") {
      inconsistent++;
      if (event.groundTruthVulnerable) inconsistentButActuallyVulnerable++;
      continue;
    }
    const isAlert = event.class !== "normal";
    if (isAlert && event.groundTruthVulnerable) truePositives++;
    else if (isAlert && !event.groundTruthVulnerable) falsePositives++;
    else if (!isAlert && event.groundTruthVulnerable) falseNegatives++;
    else trueNegatives++;
  }

  const alerts = truePositives + falsePositives;
  const precision = alerts > 0 ? truePositives / alerts : 0;
  const recall =
    truePositives + falseNegatives > 0 ? truePositives / (truePositives + falseNegatives) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    truePositives,
    falsePositives,
    falseNegatives,
    trueNegatives,
    inconsistent,
    inconsistentButActuallyVulnerable,
    alerts,
    totalEscalations: alerts + inconsistent,
    precision,
    recall,
    f1,
  };
}
