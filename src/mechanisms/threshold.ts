import type { RawSignal, ParaClass } from "../core/types.js";

/**
 * Threshold mechanism: any isolated signal from any tool fires an alert,
 * with no context and no cross-domain correlation — a single limit crossed
 * means an alarm. Never produces "inconsistente": there's no way to
 * represent contradictory evidence in a single-threshold model.
 */
export function thresholdMechanism(signal: RawSignal): ParaClass {
  if (signal.dast.hit && signal.dast.confirmed === true) return "critico";
  if (signal.sast.hit && signal.sast.severity === "critical") return "critico";
  if (signal.sca.hit && (signal.sca.cvss ?? 0) >= 9) return "critico";

  if (signal.sast.hit && signal.sast.severity === "high") return "degradacao";
  if (signal.sca.hit && (signal.sca.cvss ?? 0) >= 7) return "degradacao";
  if (signal.dast.hit) return "degradacao";

  if (signal.sast.hit || signal.sca.hit) return "atencao";

  return "normal";
}
