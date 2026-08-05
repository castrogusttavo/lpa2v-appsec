import type { RawSignal, ParaClass } from "../core/types.js";
import { thresholdMechanism } from "./threshold.js";

/**
 * Mecanismo Rule-Based: parte do mesmo veredito do Threshold e aplica um
 * pequeno conjunto de excecoes IF-THEN previstas de antemao — igual ao
 * artigo original, isso reduz parte do ruido mas so para os padroes que o
 * autor das regras ja conhecia. Contextos novos (ex.: endpoint protegido
 * por WAF, scanner instavel, modulo depreciado, rede interna) continuam
 * gerando alarme porque nao ha regra explicita para eles.
 */
export function ruleBasedMechanism(signal: RawSignal): ParaClass {
  const base = thresholdMechanism(signal);
  if (base === "normal") return "normal";

  // Regra 1: achado apenas em codigo de teste/fixture -> suprimir.
  if (signal.codeContext.inTestOrFixture) return "normal";

  // Regra 2: janela de manutencao ou pentest autorizado -> suprimir.
  if (signal.opContext.maintenanceOrPentestWindow) return "normal";

  // Regra 3: dependencia com patch disponivel e sem exploit conhecido ->
  // rebaixar um nivel (menos urgente, mas ainda nao ignorado).
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
