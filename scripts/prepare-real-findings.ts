import { readFileSync, writeFileSync } from "node:fs";
import { parseSemgrep } from "../src/realdata/parseSemgrep.js";
import { parseSnyk } from "../src/realdata/parseSnyk.js";
import { parseZap } from "../src/realdata/parseZap.js";
import type { RealFinding } from "../src/realdata/types.js";

const REPO = process.argv[2];
if (!REPO) {
  console.error("Usage: tsx scripts/prepare-real-findings.ts <repo>  (e.g.: nexo, steel)");
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

console.log(`SAST (Semgrep): ${semgrep.length} finding(s)`);
console.log(`SCA (Snyk, deduplicated): ${snyk.length} unique finding(s)`);
console.log(`DAST (ZAP, by alert type): ${zap.length} finding(s)`);
console.log(`Total to label: ${all.length}`);

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
    "", // groundTruthVulnerable — fill in with TRUE or FALSE
    "", // notes
  ]
    .map(csvEscape)
    .join(","),
);

writeFileSync(`${DATA_DIR}labeling.csv`, [headers.join(","), ...rows].join("\n") + "\n", "utf-8");
console.log(`\nSpreadsheet generated at real-data/${REPO}/labeling.csv`);
console.log(
  `Fill in the "groundTruthVulnerable" column with TRUE or FALSE for each row (the guess* columns are just an initial guess — correct them if wrong).`,
);
