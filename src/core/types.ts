// Tipos compartilhados do dominio AppSec adaptado do artigo original
// (redes industriais -> triagem de findings de seguranca de aplicacao).

export type AssetTier = "baixa" | "media" | "alta" | "critica";

export interface Asset {
  id: string;
  name: string;
  tier: AssetTier;
  /** Servico exposto publicamente (equivalente a "ativo exposto" na planta). */
  publicFacing: boolean;
  hasAuthMiddleware: boolean;
}

/** Sinal bruto de SAST (ex.: Semgrep) para um ativo em um tick de scan. */
export interface SastSignal {
  hit: boolean;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  /** Caminho de codigo alcancavel em runtime; null = desconhecido. */
  reachable: boolean | null;
}

/** Sinal bruto de SCA (ex.: Snyk) para um ativo em um tick de scan. */
export interface ScaSignal {
  hit: boolean;
  cvss: number | null;
  patchAvailable: boolean | null;
  exploitMaturity: "none" | "poc" | "active" | null;
}

/** Sinal bruto de DAST (ex.: ZAP) para um ativo em um tick de scan. */
export interface DastSignal {
  hit: boolean;
  /** Exploracao confirmada em runtime; null = deteccao passiva, sem confirmacao ativa (ex.: scan baseline) nem recusa (ex.: endpoint inacessivel). */
  confirmed: boolean | null;
  /**
   * Severidade da propria ferramenta para deteccoes passivas (confirmed
   * === null) — ex.: risk rating do ZAP baseline. Ausente = incerteza pura
   * (usado pelos cenarios sinteticos); presente = gradua a evidencia como
   * SAST/SCA ja fazem por severidade/CVSS, em vez de um valor fixo unico
   * para "nao confirmado" e "risco alto nao confirmado" ao mesmo tempo.
   */
  passiveSeverity?: "info" | "low" | "medium" | "high";
}

/** Contexto de codigo (repositorio/arquivo). */
export interface CodeContextSignal {
  inTestOrFixture: boolean;
  suppressedPreviously: boolean;
  deprecatedModule: boolean;
}

/** Contexto operacional (ambiente/rota). */
export interface OpContextSignal {
  maintenanceOrPentestWindow: boolean;
  lowTrafficStaging: boolean;
  /** VPN/rede interna reduz severidade pratica mesmo com achado tecnico valido. */
  internalOnlyNetwork: boolean;
}

export interface RawSignal {
  sast: SastSignal;
  sca: ScaSignal;
  dast: DastSignal;
  codeContext: CodeContextSignal;
  opContext: OpContextSignal;
}

/** Um evento simulado: um ativo, em um tick de scan, dentro de um cenario. */
export interface SimEvent {
  assetId: string;
  scenarioId: string;
  tick: number;
  signal: RawSignal;
  /** Verdade fundamental definida pelo simulador (nao visivel aos mecanismos). */
  groundTruthVulnerable: boolean;
}

export type ParaClass =
  | "normal"
  | "atencao"
  | "degradacao"
  | "critico"
  | "inconsistente";

export type MechanismName = "threshold" | "rule-based" | "lpa2v-cluster";

export interface ClassifiedEvent {
  assetId: string;
  scenarioId: string;
  tick: number;
  mechanism: MechanismName;
  class: ParaClass;
  groundTruthVulnerable: boolean;
}
