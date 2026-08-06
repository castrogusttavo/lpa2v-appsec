// Normalized real finding, extracted from raw Semgrep/Snyk/ZAP output.
// Unlike the synthetic scenarios (where an "event" already carries
// simultaneous signal from several domains about the SAME question), most
// real findings here are independent: a SAST finding is about an XSS, an
// SCA finding is about a dependency — they aren't multi-domain evidence
// about the same risk. They only correlate when they actually point at
// the same component/route.

export interface RealFinding {
  id: string;
  source: "sast" | "sca" | "dast";
  title: string;
  location: string;
  severityRaw: string;
  detail: string;
  instanceCount: number;
  /** Heuristics — initial guesses for a human to correct in the spreadsheet, not ground truth. */
  guessDevOnly: boolean;
  guessTestFile: boolean;
  guessPublicFacing: boolean;
  /** Original tool record (SemgrepResult/SnykVuln/ZapAlert) to pull extra fields from on demand. */
  raw: unknown;
}

export interface LabeledFinding extends RealFinding {
  groundTruthVulnerable: boolean | null;
  notes: string;
}
