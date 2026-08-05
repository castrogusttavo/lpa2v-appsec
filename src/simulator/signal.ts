import type {
  RawSignal,
  SastSignal,
  ScaSignal,
  DastSignal,
  CodeContextSignal,
  OpContextSignal,
} from "../core/types.js";

const CLEAN_SAST: SastSignal = { hit: false, severity: "info", confidence: "low", reachable: null };
const CLEAN_SCA: ScaSignal = { hit: false, cvss: null, patchAvailable: null, exploitMaturity: null };
const CLEAN_DAST: DastSignal = { hit: false, confirmed: null };
const CLEAN_CODE_CONTEXT: CodeContextSignal = {
  inTestOrFixture: false,
  suppressedPreviously: false,
  deprecatedModule: false,
};
const CLEAN_OP_CONTEXT: OpContextSignal = {
  maintenanceOrPentestWindow: false,
  lowTrafficStaging: false,
  internalOnlyNetwork: false,
};

export interface SignalOverrides {
  sast?: Partial<SastSignal>;
  sca?: Partial<ScaSignal>;
  dast?: Partial<DastSignal>;
  codeContext?: Partial<CodeContextSignal>;
  opContext?: Partial<OpContextSignal>;
}

/** Constroi um RawSignal "limpo" (nenhum achado) com overrides pontuais por sub-dominio. */
export function buildSignal(overrides: SignalOverrides = {}): RawSignal {
  return {
    sast: { ...CLEAN_SAST, ...overrides.sast },
    sca: { ...CLEAN_SCA, ...overrides.sca },
    dast: { ...CLEAN_DAST, ...overrides.dast },
    codeContext: { ...CLEAN_CODE_CONTEXT, ...overrides.codeContext },
    opContext: { ...CLEAN_OP_CONTEXT, ...overrides.opContext },
  };
}

export function lerp(from: number, to: number, t: number): number {
  return from + (to - from) * Math.min(1, Math.max(0, t));
}
