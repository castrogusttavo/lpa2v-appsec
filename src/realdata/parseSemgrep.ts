import type { RealFinding } from "./types.js";

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number };
  end: { line: number };
  extra: { severity: string; message: string };
}

interface SemgrepReport {
  results: SemgrepResult[];
}

const TEST_PATH_RE = /(__tests__|\.test\.|\.spec\.|\/tests?\/|fixtures?\/)/i;

export function parseSemgrep(report: SemgrepReport): RealFinding[] {
  return report.results.map((r, i) => {
    const location = `${r.path.replace(/^\/src\//, "")}:${r.start.line}`;
    return {
      id: `sast-${i}-${r.check_id.split(".").pop()}`,
      source: "sast",
      title: r.check_id,
      location,
      severityRaw: r.extra.severity,
      detail: r.extra.message.slice(0, 300),
      instanceCount: 1,
      guessDevOnly: false,
      guessTestFile: TEST_PATH_RE.test(r.path),
      // rota sob grupo publico do App Router (nao (private)/[workspace-slug]) -> chute de exposicao publica
      guessPublicFacing: !r.path.includes("(private)"),
      raw: r,
    };
  });
}
