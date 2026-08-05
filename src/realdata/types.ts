// Achado real normalizado, extraido do output bruto de Semgrep/Snyk/ZAP.
// Diferente dos cenarios sinteticos (onde um "evento" ja tem sinal
// simultaneo de varios dominios sobre a MESMA questao), a maioria dos
// achados reais aqui e independente: um finding do SAST fala de um XSS,
// um finding do SCA fala de uma dependencia — nao sao evidencia
// multi-dominio sobre o mesmo risco. So correlacionam quando de fato
// apontam pro mesmo componente/rota.

export interface RealFinding {
  id: string;
  source: "sast" | "sca" | "dast";
  title: string;
  location: string;
  severityRaw: string;
  detail: string;
  instanceCount: number;
  /** Heuristicas — chutes iniciais para o humano corrigir na planilha, nao verdade. */
  guessDevOnly: boolean;
  guessTestFile: boolean;
  guessPublicFacing: boolean;
  /** Registro original da ferramenta (SemgrepResult/SnykVuln/ZapAlert) para extrair campos extras sob demanda. */
  raw: unknown;
}

export interface LabeledFinding extends RealFinding {
  groundTruthVulnerable: boolean | null;
  notes: string;
}
