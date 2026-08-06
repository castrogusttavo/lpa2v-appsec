// Shared domain types: AppSec finding triage (SAST/SCA/DAST) via the
// LPA2v cluster.

export type AssetTier = "baixa" | "media" | "alta" | "critica";

export interface Asset {
  id: string;
  name: string;
  tier: AssetTier;
  /** Publicly exposed service. */
  publicFacing: boolean;
  hasAuthMiddleware: boolean;
}

/** Raw SAST signal (e.g. Semgrep) for an asset at a scan tick. */
export interface SastSignal {
  hit: boolean;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  /** Reachable at runtime; null = unknown. */
  reachable: boolean | null;
}

/** Raw SCA signal (e.g. Snyk) for an asset at a scan tick. */
export interface ScaSignal {
  hit: boolean;
  cvss: number | null;
  patchAvailable: boolean | null;
  exploitMaturity: "none" | "poc" | "active" | null;
}

/** Raw DAST signal (e.g. OWASP ZAP) for an asset at a scan tick. */
export interface DastSignal {
  hit: boolean;
  /** Confirmed runtime exploitation; null = passive detection (e.g. baseline scan), no active confirmation and no refutation (e.g. unreachable target). */
  confirmed: boolean | null;
  /**
   * The tool's own severity for passive detections (confirmed === null) —
   * e.g. ZAP baseline's risk rating. Absent = pure uncertainty (used by
   * the synthetic scenarios); present = grades the evidence by
   * severity/CVSS the way SAST/SCA already do, instead of one fixed value
   * for both "unconfirmed" and "high-risk but unconfirmed" at once.
   */
  passiveSeverity?: "info" | "low" | "medium" | "high";
}

/** Code context (repository/file). */
export interface CodeContextSignal {
  inTestOrFixture: boolean;
  suppressedPreviously: boolean;
  deprecatedModule: boolean;
}

/** Operational context (environment/route). */
export interface OpContextSignal {
  maintenanceOrPentestWindow: boolean;
  lowTrafficStaging: boolean;
  /** VPN/internal network reduces practical severity even for a technically valid finding. */
  internalOnlyNetwork: boolean;
}

export interface RawSignal {
  sast: SastSignal;
  sca: ScaSignal;
  dast: DastSignal;
  codeContext: CodeContextSignal;
  opContext: OpContextSignal;
}

/** A simulated event: one asset, at one scan tick, within a scenario. */
export interface SimEvent {
  assetId: string;
  scenarioId: string;
  tick: number;
  signal: RawSignal;
  /** Ground truth defined by the simulator (not visible to the mechanisms). */
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
