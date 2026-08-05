// Nucleo da logica paraconsistente anotada de dois valores (LPA2v).
//
// Para uma proposicao P ("este achado e uma vulnerabilidade real"), um
// neuronio paraconsistente estima:
//   mu     (grau de evidencia FAVORAVEL a P)     em [0, 1]
//   lambda (grau de evidencia DESFAVORAVEL a P)  em [0, 1]
//
// A partir daí:
//   GC  = mu - lambda        grau de certeza      em [-1, 1]
//   GCT = mu + lambda - 1    grau de contradicao   em [-1, 1]
//
// Ver artigo original (Alexandre de Carvalho, "Cluster Hierarquico de
// Neuronios Paraconsistentes LPA2v para uma Engine Inteligente de
// Monitoramento de Redes Industriais", 2026) e da Costa (1974), Abe (2015).
//
// A classificacao final em 5 classes (normal/atencao/degradacao/critico/
// inconsistente) segue a mesma nomenclatura do artigo original, mapeada
// para triagem de findings de AppSec em vez de telemetria industrial.

import type { ParaClass } from "./types.js";

export interface Evidence {
  mu: number;
  lambda: number;
}

export interface ParaconsistentThresholds {
  /** GCT a partir do qual o estado passa a ser "inconsistente", independente de GC. */
  contradiction: number;
  /** GC minimo para cada nivel ascendente de severidade. */
  attention: number;
  degradation: number;
  critical: number;
}

export const DEFAULT_THRESHOLDS: ParaconsistentThresholds = {
  contradiction: 0.5,
  attention: 0.15,
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
 * Combina evidencias de multiplos neuronios (dominios) em uma evidencia
 * agregada, por media ponderada de mu e de lambda — e assim que o neuronio
 * mestre do cluster hierarquico agrega os neuronios especializados.
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
 * Classificacao do cluster hierarquico: usa DUAS evidencias.
 *
 * `aggregated` (media ponderada de mu e de lambda entre os neuronios de
 * dominio) mede o CONSENSO — o quanto os dominios concordam que ha risco
 * real — e decide o ranking normal/atencao/degradacao/critico.
 *
 * `contradiction` (o MAIOR mu entre os dominios vs. o MAIOR lambda entre os
 * dominios, possivelmente de dominios diferentes) mede o CONFLITO — se
 * algum dominio afirma risco com forca enquanto outro o refuta com forca.
 *
 * A media ponderada por si so dilui contradicoes reais: se SAST diz "muito
 * favoravel" (mu alto) e DAST diz "muito desfavoravel" (lambda alto), a
 * media de mu e a media de lambda tendem ao centro e o GCT resultante fica
 * baixo — exatamente o oposto do que a logica paraconsistente deveria
 * capturar (preservar as duas evidencias fortes, nao apaga-las na media).
 * Por isso o teste de contradicao usa os extremos entre dominios, nao a
 * media.
 */
export function classifyCluster(
  aggregated: Evidence,
  contradiction: Evidence,
  thresholds: ParaconsistentThresholds = DEFAULT_THRESHOLDS,
): ParaClass {
  if (contradictionDegree(contradiction) >= thresholds.contradiction) return "inconsistente";
  return rankByCertainty(certaintyDegree(aggregated), thresholds);
}
