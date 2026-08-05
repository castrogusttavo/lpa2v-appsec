import type { RealFinding } from "./types.js";

interface SnykVuln {
  id: string;
  title: string;
  severity: string;
  packageName: string;
  version: string;
  from: string[];
  isUpgradable?: boolean;
  upgradePath?: (string | false)[];
  cvssScore?: number;
}

interface SnykRun {
  vulnerabilities?: SnykVuln[];
}

const DEV_TOOL_RE =
  /^(eslint|@types\/|vitest|typescript|tsx$|biome|husky|commitlint|semgrep|prettier|@biomejs\/|lint-staged)/i;

/**
 * `snyk test --all-projects` escaneia varios manifestos (app + bundles
 * gerados em .next/standalone/**), entao a MESMA vulnerabilidade de
 * dependencia aparece varias vezes — uma por manifesto. Deduplicamos por
 * (packageName, id) para o achado real virar 1 linha na planilha, nao N.
 */
export function parseSnyk(runs: SnykRun[]): RealFinding[] {
  const byKey = new Map<string, { vuln: SnykVuln; count: number }>();

  for (const run of runs) {
    for (const vuln of run.vulnerabilities ?? []) {
      const key = `${vuln.packageName}@${vuln.version}::${vuln.id}`;
      const existing = byKey.get(key);
      if (existing) existing.count++;
      else byKey.set(key, { vuln, count: 1 });
    }
  }

  return Array.from(byKey.values()).map(({ vuln, count }, i) => {
    const directDep = vuln.from[1] ?? vuln.from[0] ?? "";
    return {
      id: `sca-${i}-${vuln.packageName}`,
      source: "sca",
      title: vuln.title,
      location: `${vuln.packageName}@${vuln.version}`,
      severityRaw: vuln.severity,
      detail: `via ${vuln.from.join(" > ")} | upgradable: ${vuln.isUpgradable ?? "?"}`,
      instanceCount: count,
      guessDevOnly: DEV_TOOL_RE.test(directDep),
      guessTestFile: false,
      guessPublicFacing: true,
      raw: vuln,
    };
  });
}
