import { readFileSync, writeFileSync } from "node:fs";
import { parseSemgrep } from "../src/realdata/parseSemgrep.js";
import { parseSnyk } from "../src/realdata/parseSnyk.js";
import { parseZap } from "../src/realdata/parseZap.js";
import type { RealFinding } from "../src/realdata/types.js";
import type { Asset, RawSignal, ClassifiedEvent, MechanismName } from "../src/core/types.js";
import { buildSignal } from "../src/simulator/signal.js";
import { thresholdMechanism } from "../src/mechanisms/threshold.js";
import { ruleBasedMechanism } from "../src/mechanisms/ruleBased.js";
import { makeLpa2vMechanism } from "../src/mechanisms/lpa2v.js";
import { computeConfusion } from "../src/metrics/confusion.js";
import { printTable, fmtPct } from "../src/report/table.js";

const REPOS = ["nexo", "steel", "freecodecamp", "plane", "portfolio"];

interface LabelRow {
  id: string;
  groundTruthVulnerable: boolean;
  guessDevOnly: boolean;
  guessTestFile: boolean;
  guessPublicFacing: boolean;
}

/**
 * Minimal but correct CSV parser (RFC4180): quoted fields can contain
 * commas, escaped quotes (""), and LINE BREAKS — which does happen in the
 * `detail` column (scanner text with an embedded \n). A naive split("\n")
 * breaks the line mid-field and misaligns the columns for the rest of the
 * file; that's why this is tokenized character by character.
 */
function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        inQuotes = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  const [headers, ...dataRows] = rows;
  return dataRows
    .filter((r) => r.some((cell) => cell !== ""))
    .map((cells) => {
      const record: Record<string, string> = {};
      (headers ?? []).forEach((h, i) => (record[h] = cells[i] ?? ""));
      return record;
    });
}

function loadRepo(repo: string): { findings: RealFinding[]; labels: Map<string, LabelRow> } {
  const dir = new URL(`../real-data/${repo}/`, import.meta.url).pathname;
  const readJson = <T>(name: string): T => JSON.parse(readFileSync(`${dir}${name}`, "utf-8"));

  const semgrep = parseSemgrep(readJson("semgrep-results.json"));
  const snykRaw = readJson<unknown>("snyk-results.json");
  const snyk = parseSnyk(Array.isArray(snykRaw) ? snykRaw : [snykRaw as never]);
  const zap = parseZap(readJson("zap-results.json"));

  // Prefix the id with the repo — the parsers generate short ids (e.g.
  // "sca-0-next") that would collide across different repos once combined.
  const findings = [...semgrep, ...snyk, ...zap].map((f) => ({ ...f, id: `${repo}::${f.id}` }));

  const csvText = readFileSync(`${dir}labeled.csv`, "utf-8");
  const labels = new Map<string, LabelRow>();
  for (const row of parseCsv(csvText)) {
    const id = `${repo}::${row.id ?? ""}`;
    labels.set(id, {
      id,
      groundTruthVulnerable: row.groundTruthVulnerable?.trim().toUpperCase() === "TRUE",
      guessDevOnly: row.guessDevOnly?.trim().toUpperCase() === "TRUE",
      guessTestFile: row.guessTestFile?.trim().toUpperCase() === "TRUE",
      guessPublicFacing: row.guessPublicFacing?.trim().toUpperCase() === "TRUE",
    });
  }

  const missing = findings.filter((f) => !labels.has(f.id));
  if (missing.length > 0) {
    console.error(`WARNING (${repo}): ${missing.length} finding(s) without a label:`, missing.map((f) => f.id));
    process.exit(1);
  }

  return { findings, labels };
}

const SEMGREP_SEVERITY: Record<string, RawSignal["sast"]["severity"]> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "info",
};

function buildRawSignal(f: RealFinding, label: LabelRow): { signal: RawSignal; asset: Asset } {
  const overrides: Parameters<typeof buildSignal>[0] = {
    codeContext: {
      inTestOrFixture: label.guessTestFile,
      // There's no dedicated "build-only dependency" field in the original
      // synthetic schema; we reuse deprecatedModule as a deliberate proxy
      // (same practical semantics: low real priority).
      deprecatedModule: label.guessDevOnly,
    },
    opContext: {
      internalOnlyNetwork: !label.guessPublicFacing,
    },
  };

  if (f.source === "sast") {
    const raw = f.raw as { extra: { severity: string } };
    overrides.sast = {
      hit: true,
      severity: SEMGREP_SEVERITY[raw.extra.severity] ?? "medium",
      confidence: "medium", // the Semgrep JSON used didn't include metadata.confidence
      reachable: null,
    };
  } else if (f.source === "sca") {
    const raw = f.raw as { cvssScore?: number; isUpgradable?: boolean };
    const cvss = raw.cvssScore ?? 5;
    overrides.sca = {
      hit: true,
      cvss,
      patchAvailable: raw.isUpgradable ?? null,
      exploitMaturity: cvss >= 9 ? "poc" : "none", // the Snyk CLI didn't provide real exploitMaturity
    };
  } else {
    const raw = f.raw as { riskdesc: string };
    // ZAP's riskdesc comes as "Medium (High)" = "{risk} ({confidence})";
    // we use risk (not confidence) to grade the passive evidence.
    const risk = raw.riskdesc.split(" (")[0]?.toLowerCase() ?? "";
    const passiveSeverity =
      risk === "high" ? "high" : risk === "medium" ? "medium" : risk === "low" ? "low" : "info";
    overrides.dast = { hit: true, confirmed: null, passiveSeverity }; // baseline scan: passive detection, not confirmed exploitation
  }

  const asset: Asset = {
    id: f.id,
    name: f.location,
    tier: "media",
    publicFacing: label.guessPublicFacing,
    hasAuthMiddleware: !label.guessPublicFacing,
  };

  return { signal: buildSignal(overrides), asset };
}

const mechanisms: MechanismName[] = ["threshold", "rule-based", "lpa2v-cluster"];
const classifiedByRepo: Record<string, Record<MechanismName, ClassifiedEvent[]>> = {};
const classifiedAll: Record<MechanismName, ClassifiedEvent[]> = {
  threshold: [],
  "rule-based": [],
  "lpa2v-cluster": [],
};

for (const repo of REPOS) {
  const { findings, labels } = loadRepo(repo);
  const lpa2v = makeLpa2vMechanism(); // fresh instance per repo: no reason for one repo's asset to "persist" against another's
  const perRepo: Record<MechanismName, ClassifiedEvent[]> = {
    threshold: [],
    "rule-based": [],
    "lpa2v-cluster": [],
  };

  for (const f of findings) {
    const label = labels.get(f.id);
    if (!label) continue;
    const { signal, asset } = buildRawSignal(f, label);
    const base = {
      assetId: f.id,
      scenarioId: `${repo}/${f.source}`,
      tick: 0,
      groundTruthVulnerable: label.groundTruthVulnerable,
    };

    perRepo.threshold.push({ ...base, mechanism: "threshold", class: thresholdMechanism(signal) });
    perRepo["rule-based"].push({ ...base, mechanism: "rule-based", class: ruleBasedMechanism(signal) });

    let lpa2vClass = lpa2v(f.id, signal, asset);
    for (let tick = 1; tick < 3; tick++) lpa2vClass = lpa2v(f.id, signal, asset);
    perRepo["lpa2v-cluster"].push({ ...base, mechanism: "lpa2v-cluster", class: lpa2vClass });
  }

  classifiedByRepo[repo] = perRepo;
  for (const m of mechanisms) classifiedAll[m].push(...perRepo[m]);
}

// --- Report (console output stays pt-BR: matches this project's write-up) ---
console.log(`\nLPA2v-AppSec — validacao contra achados reais (${REPOS.length} repositorios)\n`);

console.log("Por repositorio\n");
const perRepoRows = REPOS.flatMap((repo) => {
  const total = classifiedByRepo[repo]!.threshold.length;
  return mechanisms.map((m) => {
    const c = computeConfusion(classifiedByRepo[repo]![m]);
    return [repo, total, m, fmtPct(c.precision), fmtPct(c.recall), fmtPct(c.f1), c.truePositives, c.falsePositives, c.falseNegatives];
  });
});
printTable(["Repo", "N achados", "Mecanismo", "Precisao", "Recall", "F1", "TP", "FP", "FN"], perRepoRows);

console.log("\nCombinado (todos os repositorios)\n");
const totalN = classifiedAll.threshold.length;
console.log(`Total de achados rotulados: ${totalN}\n`);
const combinedRows = mechanisms.map((m) => {
  const c = computeConfusion(classifiedAll[m]);
  return [
    m,
    fmtPct(c.precision),
    fmtPct(c.recall),
    fmtPct(c.f1),
    c.truePositives,
    c.falsePositives,
    c.falseNegatives,
    c.alerts,
    c.inconsistent,
  ];
});
printTable(["Mecanismo", "Precisao", "Recall", "F1", "TP", "FP", "FN", "Alertas", "Inconsist."], combinedRows);

// --- Export for the figures (plots/make_figures.py) ---
const exportPath = new URL("../real-data/results.json", import.meta.url).pathname;
writeFileSync(
  exportPath,
  JSON.stringify(
    {
      repos: REPOS,
      perRepo: Object.fromEntries(
        REPOS.map((repo) => [
          repo,
          {
            n: classifiedByRepo[repo]!.threshold.length,
            mechanisms: Object.fromEntries(
              mechanisms.map((m) => [m, computeConfusion(classifiedByRepo[repo]![m])]),
            ),
          },
        ]),
      ),
      combined: {
        n: totalN,
        mechanisms: Object.fromEntries(mechanisms.map((m) => [m, computeConfusion(classifiedAll[m])])),
      },
    },
    null,
    2,
  ),
  "utf-8",
);
console.log(`\nExportado para real-data/results.json (uso dos graficos)`);
