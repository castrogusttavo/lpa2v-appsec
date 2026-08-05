import type { RawSignal, ParaClass } from "../core/types.js";

/**
 * Mecanismo Threshold: qualquer sinal isolado de qualquer ferramenta gera
 * alerta, sem contexto e sem correlacao entre dominios — equivalente ao
 * "threshold" do artigo original (limite individual ultrapassado = alarme).
 * Nunca produz "inconsistente": nao ha como representar evidencia
 * contraditoria em um modelo de limiar unico.
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
