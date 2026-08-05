import type { Asset, RawSignal } from "../core/types.js";
import { combineEvidence, type Evidence } from "../core/paraconsistent.js";
import { sastNeuron } from "../neurons/sast.js";
import { scaNeuron } from "../neurons/sca.js";
import { dastNeuron } from "../neurons/dast.js";
import { codeContextNeuron } from "../neurons/codeContext.js";
import { opContextNeuron } from "../neurons/opContext.js";

/**
 * Pesos dos neuronios de dominio na agregacao do neuronio mestre.
 * SAST/SCA/DAST sao detectores primarios. Contexto de codigo e contexto
 * operacional recebem peso maior que um detector individual porque, quando
 * disparam, refletem metadado quase-factual (esta em teste, esta em janela
 * de manutencao autorizada) em vez de um match probabilistico — devem ser
 * capazes de anular o veredito de um unico detector primario, do mesmo
 * jeito que "backup autorizado" anula CPU alta no artigo original.
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

/** Neuronio mestre: agrega as evidencias dos neuronios de dominio (correlacao contextual). */
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
 * Sinal de contradicao: o maior mu entre os DETECTORES PRIMARIOS (SAST/SCA/
 * DAST) vs. o maior lambda entre eles (podem vir de detectores diferentes).
 * Preserva o caso em que um detector afirma risco com forca e outro o
 * refuta com forca, em vez de deixar a media apagar os dois extremos — ver
 * nota em `classifyCluster`.
 *
 * Contexto de codigo/operacional fica de fora deste calculo de proposito:
 * eles nao sao "mais uma opiniao sobre existir vulnerabilidade", sao
 * metadado explicativo (por que o detector disparou) — quando um contexto
 * explica um achado (ex.: janela de manutencao autorizada), o resultado
 * correto e suprimir a severidade, nao declarar um estado inconsistente
 * pedindo revisao humana.
 */
export function contradictionSignal(breakdown: DomainBreakdown): Evidence {
  const primary = [breakdown.sast, breakdown.sca, breakdown.dast];
  return {
    mu: Math.max(...primary.map((v) => v.mu)),
    lambda: Math.max(...primary.map((v) => v.lambda)),
  };
}
