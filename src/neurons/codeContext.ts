import type { CodeContextSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

/**
 * Neuronio de contexto de codigo — nao detecta vulnerabilidades por si so,
 * mas fornece evidencia (favoravel ou desfavoravel) sobre se um achado dos
 * detectores primarios (SAST/SCA/DAST) reflete risco real.
 */
export function codeContextNeuron(signal: CodeContextSignal): Evidence {
  // Baseline neutra (GC = 0): sem nenhuma flag, este neuronio nao tem
  // opiniao e nao deve puxar a media do cluster em nenhuma direcao.
  let mu = 0.1;
  let lambda = 0.1;

  if (signal.inTestOrFixture) lambda += 0.75;
  if (signal.suppressedPreviously) lambda += 0.4;
  if (signal.deprecatedModule) lambda += 0.3;

  return { mu: clamp01(mu), lambda: clamp01(lambda) };
}
