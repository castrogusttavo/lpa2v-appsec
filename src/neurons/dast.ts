import type { DastSignal } from "../core/types.js";
import { clamp01, type Evidence } from "../core/paraconsistent.js";

/** Neuronio de dominio DAST (ex.: OWASP ZAP) — evidencia de exploracao em runtime. */
export function dastNeuron(signal: DastSignal): Evidence {
  if (!signal.hit) {
    // DAST so ve o que consegue alcancar e testar; silencio nao e prova forte.
    return { mu: 0.05, lambda: 0.15 };
  }

  if (signal.confirmed === true) {
    return { mu: 0.9, lambda: 0.05 };
  }
  if (signal.confirmed === false) {
    // Tentativa de exploracao ativa e deliberada que falhou (ex.: bloqueada
    // por WAF) e evidencia desfavoravel forte, nao fraca — o ataque foi
    // de fato tentado em runtime e nao vingou.
    return { mu: 0.15, lambda: 0.7 };
  }
  // confirmed === null: deteccao passiva (sem tentativa ativa de explorar) OU
  // alvo inacessivel. Sem passiveSeverity, mantemos a incerteza pura
  // original (mu=lambda=neutro) — comportamento inalterado para os
  // cenarios sinteticos, nenhum dos quais define esse campo.
  if (!signal.passiveSeverity) {
    return { mu: 0.3, lambda: 0.3 };
  }
  const base: Record<NonNullable<DastSignal["passiveSeverity"]>, Evidence> = {
    info: { mu: 0.35, lambda: 0.2 },
    low: { mu: 0.5, lambda: 0.15 },
    medium: { mu: 0.65, lambda: 0.1 },
    high: { mu: 0.8, lambda: 0.1 },
  };
  return base[signal.passiveSeverity];
}
