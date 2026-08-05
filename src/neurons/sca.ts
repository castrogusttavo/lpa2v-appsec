import type { ScaSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

/** Neuronio de dominio SCA (ex.: Snyk) — evidencia de dependencia vulneravel. */
export function scaNeuron(signal: ScaSignal): Evidence {
  if (!signal.hit) {
    // SCA tem visibilidade quase completa sobre dependencias declaradas,
    // entao a ausencia de match e evidencia relativamente mais confiavel
    // de seguranca do que a ausencia de match de SAST/DAST.
    return { mu: 0.03, lambda: 0.2 };
  }

  let mu = (signal.cvss ?? 5) / 10;
  let lambda = 0.1;

  if (signal.exploitMaturity === "active") mu += 0.2;
  else if (signal.exploitMaturity === "poc") mu += 0.1;

  if (signal.patchAvailable === true) lambda += 0.05;

  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}
