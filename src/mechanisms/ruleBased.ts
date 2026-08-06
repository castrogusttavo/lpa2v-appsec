import type { RawSignal, ParaClass } from "../core/types.js";
import { thresholdMechanism } from "./threshold.js";

/**
 * Rule-Based mechanism: starts from the same verdict as Threshold and
 * applies a small set of IF-THEN exceptions anticipated in advance — this
 * cuts some of the noise, but only for the patterns the rule author already
 * knew about. New contexts (e.g. a WAF-protected endpoint, a flaky scanner,
 * a deprecated module, an internal-only network) still trigger an alarm
 * because there's no explicit rule for them.
 */
export function ruleBasedMechanism(signal: RawSignal): ParaClass {
  const base = thresholdMechanism(signal);
  if (base === "normal") return "normal";

  // Rule 1: finding only in test/fixture code -> suppress.
  if (signal.codeContext.inTestOrFixture) return "normal";

  // Rule 2: maintenance window or authorized pentest -> suppress.
  if (signal.opContext.maintenanceOrPentestWindow) return "normal";

  // Rule 3: dependency with a patch available and no known exploit ->
  // downgrade one level (less urgent, but not ignored outright).
  if (
    !signal.sast.hit &&
    !signal.dast.hit &&
    signal.sca.hit &&
    signal.sca.patchAvailable === true &&
    signal.sca.exploitMaturity === "none"
  ) {
    if (base === "critico") return "degradacao";
    if (base === "degradacao") return "atencao";
    return "normal";
  }

  return base;
}
