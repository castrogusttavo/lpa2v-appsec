import type { ClassifiedEvent, ParaClass, SimEvent } from "../core/types.js";

const RANK: Record<Exclude<ParaClass, "inconsistente">, number> = {
  normal: 0,
  atencao: 1,
  degradacao: 2,
  critico: 3,
};

/**
 * Tick at which the raw evidence unambiguously crosses the hard limit that
 * the Threshold mechanism would use to classify as critical. This is the
 * "objective" reference point against which we measure anticipation/lag.
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
 * First tick at which the mechanism reaches AT LEAST the given rank
 * (default: degradacao). We don't use "any alert" as the comparison
 * because Threshold flags "atencao" from a single isolated hit, with no
 * selectivity at all — comparing by the first raw alert would artificially
 * favor the noisier mechanism. Comparing from "degradacao" up requires the
 * signal to already have some substance across every mechanism, making the
 * anticipation comparison fair.
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
  /** Positive = the mechanism anticipated the problem; negative = it detected it late. */
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
