import { readFileSync, writeFileSync, existsSync, appendFileSync } from "node:fs";
import { parseSemgrep } from "../src/realdata/parseSemgrep.js";
import { parseSnyk } from "../src/realdata/parseSnyk.js";
import { parseZap } from "../src/realdata/parseZap.js";
import type { RealFinding } from "../src/realdata/types.js";
import type { Asset, RawSignal, ParaClass } from "../src/core/types.js";
import { buildSignal } from "../src/simulator/signal.js";
import { makeLpa2vMechanism } from "../src/mechanisms/lpa2v.js";

/**
 * Production triage entrypoint: classifies real SAST/SCA/DAST findings with
 * no ground-truth labels (unlike scripts/run-real-findings.ts, which is a
 * research-validation script that requires a labeled.csv). This is what a
 * CI pipeline runs on every scan — it only has the parsers' own heuristic
 * guesses (guessDevOnly/guessTestFile/guessPublicFacing), not a human
 * verdict, so there is no confusion matrix here, only classification.
 *
 * Usage:
 *   tsx scripts/triage-ci.ts --semgrep semgrep.json --snyk snyk.json --zap zap.json --out triage-results.json
 *
 * Any of --semgrep/--snyk/--zap may be omitted if that scanner didn't run in
 * this job — the cluster classifies with whatever evidence domains are
 * present (a missing domain just contributes its neutral baseline, same as
 * a scenario where that scanner had no hit).
 */

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf-8"));
}

const semgrepPath = arg("semgrep");
const snykPath = arg("snyk");
const zapPath = arg("zap");
const outPath = arg("out") ?? "triage-results.json";

const findings: RealFinding[] = [];

if (semgrepPath && existsSync(semgrepPath)) {
  findings.push(...parseSemgrep(readJson(semgrepPath)));
}
if (snykPath && existsSync(snykPath)) {
  const raw = readJson<unknown>(snykPath);
  findings.push(...parseSnyk(Array.isArray(raw) ? raw : [raw as never]));
}
if (zapPath && existsSync(zapPath)) {
  findings.push(...parseZap(readJson(zapPath)));
}

if (findings.length === 0) {
  console.log("No scanner input provided (or all inputs empty) — nothing to triage.");
  writeFileSync(outPath, JSON.stringify({ findings: [] }, null, 2), "utf-8");
  process.exit(0);
}

const SEMGREP_SEVERITY: Record<string, RawSignal["sast"]["severity"]> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "info",
};

function buildRawSignal(f: RealFinding): { signal: RawSignal; asset: Asset } {
  const overrides: Parameters<typeof buildSignal>[0] = {
    codeContext: {
      inTestOrFixture: f.guessTestFile,
      deprecatedModule: f.guessDevOnly,
    },
    opContext: {
      internalOnlyNetwork: !f.guessPublicFacing,
    },
  };

  if (f.source === "sast") {
    const raw = f.raw as { extra: { severity: string } };
    overrides.sast = {
      hit: true,
      severity: SEMGREP_SEVERITY[raw.extra.severity] ?? "medium",
      confidence: "medium",
      reachable: null,
    };
  } else if (f.source === "sca") {
    const raw = f.raw as { cvssScore?: number; isUpgradable?: boolean };
    const cvss = raw.cvssScore ?? 5;
    overrides.sca = {
      hit: true,
      cvss,
      patchAvailable: raw.isUpgradable ?? null,
      exploitMaturity: cvss >= 9 ? "poc" : "none",
    };
  } else {
    const raw = f.raw as { riskdesc: string };
    const risk = raw.riskdesc.split(" (")[0]?.toLowerCase() ?? "";
    const passiveSeverity =
      risk === "high" ? "high" : risk === "medium" ? "medium" : risk === "low" ? "low" : "info";
    overrides.dast = { hit: true, confirmed: null, passiveSeverity };
  }

  const asset: Asset = {
    id: f.id,
    name: f.location,
    tier: "media",
    publicFacing: f.guessPublicFacing,
    hasAuthMiddleware: !f.guessPublicFacing,
  };

  return { signal: buildSignal(overrides), asset };
}

const lpa2v = makeLpa2vMechanism();
const RANK: Record<ParaClass, number> = {
  normal: 0,
  atencao: 1,
  degradacao: 2,
  critico: 3,
  inconsistente: 1.5,
};

const results = findings.map((f) => {
  const { signal, asset } = buildRawSignal(f);
  let cls: ParaClass = "normal";
  // Same 3-tick warm-up used by run-real-findings.ts: a single CI run has no
  // real time axis, so this reaches the persistence window's steady state
  // for a one-shot classification instead of leaving it artificially cold.
  for (let tick = 0; tick < 3; tick++) cls = lpa2v(f.id, signal, asset);
  return {
    id: f.id,
    source: f.source,
    title: f.title,
    location: f.location,
    severityRaw: f.severityRaw,
    class: cls,
  };
});

writeFileSync(outPath, JSON.stringify({ findings: results }, null, 2), "utf-8");

const bySource = { sast: 0, sca: 0, dast: 0 };
for (const f of findings) bySource[f.source]++;

// "Alerta" segue a mesma definição de src/metrics/confusion.ts: qualquer
// classe != normal e != inconsistente — ou seja, "atenção" já é alerta,
// não deve ser silenciosamente agrupada com "normal".
const criticos = results.filter((r) => r.class === "critico");
const inconsistentes = results.filter((r) => r.class === "inconsistente");
const degradacao = results.filter((r) => r.class === "degradacao");
const atencao = results.filter((r) => r.class === "atencao");
const normais = results.filter((r) => r.class === "normal");

// O que entra na Issue/relatório de revisão: tudo que não é puro "normal".
const forReview = [...criticos, ...inconsistentes, ...degradacao, ...atencao];

console.log(`\nLPA2v-AppSec — triagem de CI (${findings.length} achados: ${bySource.sast} SAST, ${bySource.sca} SCA, ${bySource.dast} DAST)\n`);
console.log(`  crítico:       ${criticos.length}`);
console.log(`  inconsistente: ${inconsistentes.length} (evidência contraditória — revisão humana)`);
console.log(`  degradação:    ${degradacao.length}`);
console.log(`  atenção:       ${atencao.length}`);
console.log(`  normal:        ${normais.length}\n`);

function classFlag(cls: ParaClass): string {
  return cls === "critico" ? "🔴" : cls === "inconsistente" ? "🟣" : cls === "degradacao" ? "🟠" : "🟡";
}
function mdRow(r: (typeof results)[number]): string {
  return `| ${classFlag(r.class)} | ${r.source.toUpperCase()} | ${r.title} | ${r.location} | ${r.class} |`;
}
function reviewTable(): string[] {
  const lines = ["| | Fonte | Achado | Local | Classe |", "|---|---|---|---|---|"];
  for (const r of forReview) lines.push(mdRow(r));
  return lines;
}

const summaryPath = process.env.GITHUB_STEP_SUMMARY;
if (summaryPath) {
  const lines = [
    "## LPA2v-AppSec — Triagem contextual",
    "",
    `${findings.length} achados correlacionados (${bySource.sast} SAST, ${bySource.sca} SCA, ${bySource.dast} DAST).`,
    "",
    `| | | | | |`,
    `|---|---|---|---|---|`,
    `| 🔴 crítico | ${criticos.length} | 🟣 inconsistente | ${inconsistentes.length} | |`,
    `| 🟠 degradação | ${degradacao.length} | 🟡 atenção | ${atencao.length} | ⚪ normal ${normais.length} |`,
    "",
  ];
  if (forReview.length > 0) lines.push(...reviewTable(), "");
  appendFileSync(summaryPath, lines.join("\n"), "utf-8");
}

// Corpo pronto para virar Issue (gerado sempre; o workflow decide, via
// needs_review/outputs abaixo, se de fato abre a Issue — evitar Issue vazia
// quando não há nada para revisar).
const issueBodyPath = arg("issue-body") ?? "triage-issue.md";
const issueLines = [
  `Triagem automática do cluster LPA2v sobre ${findings.length} achados (${bySource.sast} SAST, ${bySource.sca} SCA, ${bySource.dast} DAST).`,
  "",
  `- 🔴 crítico: **${criticos.length}**`,
  `- 🟣 inconsistente (evidência contraditória entre detectores): **${inconsistentes.length}**`,
  `- 🟠 degradação: **${degradacao.length}**`,
  `- 🟡 atenção: **${atencao.length}**`,
  "",
  "### Achados que pedem revisão",
  "",
  ...reviewTable(),
  "",
  `_Gerado automaticamente a partir de ${outPath}. Achados classificados "normal" (${normais.length}) foram omitidos._`,
];
writeFileSync(issueBodyPath, issueLines.join("\n"), "utf-8");

const githubOutput = process.env.GITHUB_OUTPUT;
if (githubOutput) {
  appendFileSync(
    githubOutput,
    [
      `needs_review=${forReview.length > 0}`,
      `critico_count=${criticos.length}`,
      `inconsistente_count=${inconsistentes.length}`,
      `review_count=${forReview.length}`,
      "",
    ].join("\n"),
    "utf-8",
  );
}

if (criticos.length > 0) {
  console.error(`FALHA: ${criticos.length} achado(s) classificado(s) como crítico pelo cluster LPA2v.`);
  process.exit(1);
}

console.log("OK: nenhum achado crítico segundo o cluster LPA2v.");
