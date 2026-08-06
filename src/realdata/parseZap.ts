import type { RealFinding } from "./types.js";

interface ZapInstance {
  uri: string;
  evidence?: string;
  otherinfo?: string;
}

interface ZapAlert {
  pluginid: string;
  name: string;
  riskdesc: string;
  instances: ZapInstance[];
}

interface ZapSite {
  alerts: ZapAlert[];
}

interface ZapReport {
  site: ZapSite[];
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")
    .slice(0, 40);
}

export function parseZap(report: ZapReport): RealFinding[] {
  const findings: RealFinding[] = [];
  let i = 0;
  for (const site of report.site) {
    for (const alert of site.alerts) {
      if (alert.instances.length === 0) continue;
      const sample = alert.instances[0];
      findings.push({
        // pluginid alone isn't unique: ZAP reuses the same plugin id
        // across distinct sub-checks (e.g. 10055 covers two CSP variants).
        id: `dast-${i++}-${alert.pluginid}-${slugify(alert.name)}`,
        source: "dast",
        title: alert.name,
        location: sample?.uri ?? "",
        severityRaw: alert.riskdesc,
        detail: (sample?.otherinfo || sample?.evidence || "").slice(0, 300),
        instanceCount: alert.instances.length,
        guessDevOnly: false,
        guessTestFile: false,
        guessPublicFacing: true,
        raw: alert,
      });
    }
  }
  return findings;
}
