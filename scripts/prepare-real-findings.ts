import { readFileSync, writeFileSync } from "node:fs";
import { parseSemgrep } from "../src/realdata/parseSemgrep.js";
import { parseSnyk } from "../src/realdata/parseSnyk.js";
import { parseZap } from "../src/realdata/parseZap.js";
import type { RealFinding } from "../src/realdata/types.js";

const REPO = process.argv[2];
if (!REPO) {
  console.error("Uso: tsx scripts/prepare-real-findings.ts <repo>  (ex.: nexo, steel)");
  process.exit(1);
}
const DATA_DIR = new URL(`../real-data/${REPO}/`, import.meta.url).pathname;

function readJson<T>(name: string): T {
  return JSON.parse(readFileSync(`${DATA_DIR}${name}`, "utf-8"));
}

const semgrep = parseSemgrep(readJson(`semgrep-results.json`));
const snykRaw = readJson<unknown>(`snyk-results.json`);
const snyk = parseSnyk(Array.isArray(snykRaw) ? snykRaw : [snykRaw as never]);
const zap = parseZap(readJson(`zap-results.json`));

const all: RealFinding[] = [...semgrep, ...snyk, ...zap];

console.log(`SAST (Semgrep): ${semgrep.length} achado(s)`);
console.log(`SCA (Snyk, deduplicado): ${snyk.length} achado(s) unico(s)`);
console.log(`DAST (ZAP, por tipo de alerta): ${zap.length} achado(s)`);
console.log(`Total para rotular: ${all.length}`);

const headers = [
  "id",
  "source",
  "title",
  "location",
  "severityRaw",
  "instanceCount",
  "guessDevOnly",
  "guessTestFile",
  "guessPublicFacing",
  "detail",
  "groundTruthVulnerable",
  "notes",
];

function csvEscape(v: unknown): string {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const rows = all.map((f) =>
  [
    f.id,
    f.source,
    f.title,
    f.location,
    f.severityRaw,
    f.instanceCount,
    f.guessDevOnly,
    f.guessTestFile,
    f.guessPublicFacing,
    f.detail,
    "", // groundTruthVulnerable — preencher com TRUE ou FALSE
    "", // notes
  ]
    .map(csvEscape)
    .join(","),
);

writeFileSync(`${DATA_DIR}labeling.csv`, [headers.join(","), ...rows].join("\n") + "\n", "utf-8");
console.log(`\nPlanilha gerada em real-data/${REPO}/labeling.csv`);
console.log(
  `Preencha a coluna "groundTruthVulnerable" com TRUE ou FALSE para cada linha (as colunas guess* sao so um chute inicial — corrija se estiver errado).`,
);
