import type { ClassifiedEvent, ParaClass, SimEvent } from "../core/types.js";

const RANK: Record<Exclude<ParaClass, "inconsistente">, number> = {
  normal: 0,
  atencao: 1,
  degradacao: 2,
  critico: 3,
};

/**
 * Tick em que a evidencia bruta cruza, sem ambiguidade, o limite rigido que
 * o mecanismo Threshold usaria para classificar como critico. E o ponto de
 * referencia "objetivo" contra o qual medimos antecipacao/atraso —
 * equivalente ao momento em que o loop Ethernet do artigo se torna
 * inequivocamente critico.
 */
export function findHardLimitTick(events: SimEvent[]): number | null {
  const hit = events
    .filter(
      (e) =>
        (e.signal.sast.hit && e.signal.sast.severity === "critical") ||
        (e.signal.sca.hit && (e.signal.sca.cvss ?? 0) >= 9) ||
        (e.signal.dast.hit && e.signal.dast.confirmed === true),
    )
    .sort((a, b) => a.tick - b.tick)[0];
  return hit ? hit.tick : null;
}

/**
 * Primeiro tick em que o mecanismo atinge PELO MENOS o rank informado
 * (padrao: degradacao). Nao usamos "qualquer alerta" como comparacao
 * porque o Threshold marca "atencao" a partir de um unico hit isolado, sem
 * nenhuma seletividade — comparar pelo primeiro alerta bruto favoreceria
 * artificialmente o mecanismo mais ruidoso. Comparar a partir de
 * "degradacao" exige que o sinal já tenha alguma substância em todos os
 * mecanismos, tornando a comparação de antecipação justa.
 */
export function findFirstTickAtRank(
  events: ClassifiedEvent[],
  minRank: number = RANK.degradacao,
): number | null {
  const hit = events
    .filter((e) => e.class !== "inconsistente" && RANK[e.class] >= minRank)
    .sort((a, b) => a.tick - b.tick)[0];
  return hit ? hit.tick : null;
}

export interface LeadTimeResult {
  hardLimitTick: number | null;
  firstEscalatedTick: number | null;
  /** Positivo = mecanismo antecipou o problema; negativo = detectou com atraso. */
  leadTicks: number | null;
}

export function computeLeadTime(
  scenarioEvents: SimEvent[],
  classifiedEvents: ClassifiedEvent[],
): LeadTimeResult {
  const hardLimitTick = findHardLimitTick(scenarioEvents);
  const firstEscalatedTick = findFirstTickAtRank(classifiedEvents, RANK.degradacao);
  const leadTicks =
    hardLimitTick !== null && firstEscalatedTick !== null
      ? hardLimitTick - firstEscalatedTick
      : null;
  return { hardLimitTick, firstEscalatedTick, leadTicks };
}
