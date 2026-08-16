import { readFileSync } from "node:fs";
import { parseSemgrep } from "../src/realdata/parseSemgrep.js";
import { parseSnyk } from "../src/realdata/parseSnyk.js";
import { parseZap } from "../src/realdata/parseZap.js";
import type { RealFinding } from "../src/realdata/types.js";
import type { Asset, RawSignal, MechanismName, ClassifiedEvent } from "../src/core/types.js";
import { buildSignal } from "../src/simulator/signal.js";
import { Lpa2vCluster } from "../src/cluster/lpa2vCluster.js";
import { DEFAULT_THRESHOLDS, type ParaconsistentThresholds } from "../src/core/paraconsistent.js";
import { computeConfusion } from "../src/metrics/confusion.js";
import { printTable, fmtPct } from "../src/report/table.js";

/**
 * Grid search over (attention, contradiction) thresholds against the 559
 * labeled real findings, to find the point that maximizes precision without
 * collapsing recall to a degenerate near-zero. Product priority (per
 * explicit direction): precision first.
 *
 * degradation/critical thresholds don't affect precision/recall at all —
 * computeConfusion treats any non-"normal", non-"inconsistente" class as
 * the same "alert" bucket, so only `attention` (the alert/normal boundary)
 * and `contradiction` (the alert/inconsistente boundary) matter here.
 */

const REPOS = ["nexo", "steel", "freecodecamp", "plane", "portfolio"];

interface LabelRow {
  id: string;
  groundTruthVulnerable: boolean;
  guessDevOnly: boolean;
  guessTestFile: boolean;
  guessPublicFacing: boolean;
}

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
  return { findings, labels };
}

const SEMGREP_SEVERITY: Record<string, RawSignal["sast"]["severity"]> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "info",
};

function buildRawSignal(f: RealFinding, label: LabelRow): { signal: RawSignal; asset: Asset } {
  const overrides: Parameters<typeof buildSignal>[0] = {
    codeContext: { inTestOrFixture: label.guessTestFile, deprecatedModule: label.guessDevOnly },
    opContext: { internalOnlyNetwork: !label.guessPublicFacing },
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
    publicFacing: label.guessPublicFacing,
    hasAuthMiddleware: !label.guessPublicFacing,
  };
  return { signal: buildSignal(overrides), asset };
}

// --- load once, reuse across the whole grid search ---
const allData: { repo: string; findings: RealFinding[]; labels: Map<string, LabelRow> }[] = REPOS.map((repo) => ({
  repo,
  ...loadRepo(repo),
}));

function runWithThresholds(thresholds: ParaconsistentThresholds): ClassifiedEvent[] {
  const events: ClassifiedEvent[] = [];
  for (const { repo, findings, labels } of allData) {
    const cluster = new Lpa2vCluster({ thresholds });
    for (const f of findings) {
      const label = labels.get(f.id);
      if (!label) continue;
      const { signal, asset } = buildRawSignal(f, label);
      let cls = cluster.classify(f.id, signal, asset);
      for (let tick = 1; tick < 3; tick++) cls = cluster.classify(f.id, signal, asset);
      events.push({
        assetId: f.id,
        scenarioId: `${repo}/${f.source}`,
        tick: 0,
        mechanism: "lpa2v-cluster" as MechanismName,
        class: cls,
        groundTruthVulnerable: label.groundTruthVulnerable,
      });
    }
  }
  return events;
}

// --- grid search ---
const attentionGrid = Array.from({ length: 21 }, (_, i) => 0.14 + i * 0.01); // 0.14..0.34, 0.01 steps
const contradictionGrid = [0.4, 0.45, 0.5, 0.55, 0.6];

interface Result {
  attention: number;
  contradiction: number;
  precision: number;
  recall: number;
  f1: number;
  tp: number;
  fp: number;
  fn: number;
  alerts: number;
}

const results: Result[] = [];
for (const attention of attentionGrid) {
  for (const contradiction of contradictionGrid) {
    const thresholds: ParaconsistentThresholds = {
      ...DEFAULT_THRESHOLDS,
      attention,
      degradation: Math.max(DEFAULT_THRESHOLDS.degradation, attention),
      critical: Math.max(DEFAULT_THRESHOLDS.critical, attention),
      contradiction,
    };
    const events = runWithThresholds(thresholds);
    const c = computeConfusion(events);
    results.push({
      attention,
      contradiction,
      precision: c.precision,
      recall: c.recall,
      f1: c.f1,
      tp: c.truePositives,
      fp: c.falsePositives,
      fn: c.falseNegatives,
      alerts: c.alerts,
    });
  }
}

console.log(`\nLPA2v-AppSec — calibracao de thresholds (grade ${results.length} combinacoes, 559 achados reais)\n`);

// Baseline (current DEFAULT_THRESHOLDS) for reference
const baseline = computeConfusion(runWithThresholds(DEFAULT_THRESHOLDS));
console.log(
  `Baseline atual (attention=${DEFAULT_THRESHOLDS.attention}, contradiction=${DEFAULT_THRESHOLDS.contradiction}): precisao=${fmtPct(baseline.precision)} recall=${fmtPct(baseline.recall)} f1=${fmtPct(baseline.f1)}\n`,
);

// Precision-first views, at a few recall floors, so precision priority doesn't collapse to a 0-alert / undefined-precision edge case
for (const recallFloor of [0.7, 0.5, 0.3, 0]) {
  const candidates = results.filter((r) => r.recall >= recallFloor && r.alerts > 0);
  if (candidates.length === 0) continue;
  candidates.sort((a, b) => b.precision - a.precision || b.f1 - a.f1);
  const best = candidates[0];
  if (!best) continue;
  console.log(
    `Recall >= ${(recallFloor * 100).toFixed(0)}%: attention=${best.attention.toFixed(2)} contradiction=${best.contradiction.toFixed(2)} -> precisao=${fmtPct(best.precision)} recall=${fmtPct(best.recall)} f1=${fmtPct(best.f1)} (TP=${best.tp} FP=${best.fp} FN=${best.fn}, ${best.alerts} alertas)`,
  );
}

// Full top-10 by precision (any recall) for visibility
console.log("\nTop 10 por precisao (qualquer recall, com pelo menos 1 alerta):\n");
const top10 = [...results].filter((r) => r.alerts > 0).sort((a, b) => b.precision - a.precision || b.recall - a.recall).slice(0, 10);
printTable(
  ["attention", "contradiction", "Precisao", "Recall", "F1", "TP", "FP", "FN", "Alertas"],
  top10.map((r) => [
    r.attention.toFixed(2),
    r.contradiction.toFixed(2),
    fmtPct(r.precision),
    fmtPct(r.recall),
    fmtPct(r.f1),
    r.tp,
    r.fp,
    r.fn,
    r.alerts,
  ]),
);

console.log("\nCurva completa (contradiction=0.40 fixo):\n");
const curve = results.filter((r) => r.contradiction === 0.4).sort((a, b) => a.attention - b.attention);
printTable(
  ["attention", "Precisao", "Recall", "F1", "TP", "FP", "FN", "Alertas"],
  curve.map((r) => [
    r.attention.toFixed(2),
    fmtPct(r.precision),
    fmtPct(r.recall),
    fmtPct(r.f1),
    r.tp,
    r.fp,
    r.fn,
    r.alerts,
  ]),
);

// --- per-repository breakdown at the chosen operating point ---
function breakdownAt(thresholds: ParaconsistentThresholds): void {
  console.log(
    `\nDetalhamento por repositorio (attention=${thresholds.attention}, contradiction=${thresholds.contradiction}):\n`,
  );
  for (const { repo, findings, labels } of allData) {
    const cluster = new Lpa2vCluster({ thresholds });
    const events: ClassifiedEvent[] = [];
    for (const f of findings) {
      const label = labels.get(f.id);
      if (!label) continue;
      const { signal, asset } = buildRawSignal(f, label);
      let cls = cluster.classify(f.id, signal, asset);
      for (let tick = 1; tick < 3; tick++) cls = cluster.classify(f.id, signal, asset);
      events.push({
        assetId: f.id,
        scenarioId: repo,
        tick: 0,
        mechanism: "lpa2v-cluster" as MechanismName,
        class: cls,
        groundTruthVulnerable: label.groundTruthVulnerable,
      });
    }
    const c = computeConfusion(events);
    console.log(
      `${repo}: N=${events.length} precisao=${fmtPct(c.precision)} recall=${fmtPct(c.recall)} (TP=${c.truePositives} FP=${c.falsePositives} FN=${c.falseNegatives})`,
    );
  }
}

breakdownAt({ ...DEFAULT_THRESHOLDS, attention: 0.18, contradiction: 0.5 });
