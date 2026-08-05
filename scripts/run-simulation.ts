import type { ClassifiedEvent, MechanismName } from "../src/core/types.js";
import { makeLpa2vMechanism } from "../src/mechanisms/lpa2v.js";
import { ruleBasedMechanism } from "../src/mechanisms/ruleBased.js";
import { thresholdMechanism } from "../src/mechanisms/threshold.js";
import { computeConfusion } from "../src/metrics/confusion.js";
import { computeLeadTime } from "../src/metrics/leadTime.js";
import { writeCsv, writeJson } from "../src/report/export.js";
import { fmtPct, printTable } from "../src/report/table.js";
import { buildSimulation } from "../src/simulator/run.js";

const SEED = Number(process.argv[2] ?? 42);

console.log(`\nLPA2v-AppSec — simulador de triagem de findings (seed=${SEED})\n`);

const sim = buildSimulation(SEED);
console.log(
  `Cenarios: ${sim.scenarios.length} | Ativos: ${sim.assets.size} | Eventos totais: ${sim.events.length}\n`,
);

const lpa2v = makeLpa2vMechanism();

const classifiedByMechanism: Record<MechanismName, ClassifiedEvent[]> = {
  threshold: [],
  "rule-based": [],
  "lpa2v-cluster": [],
};

for (const event of sim.events) {
  const asset = sim.assets.get(event.assetId);
  if (!asset) continue;

  classifiedByMechanism.threshold.push({
    assetId: event.assetId,
    scenarioId: event.scenarioId,
    tick: event.tick,
    mechanism: "threshold",
    class: thresholdMechanism(event.signal),
    groundTruthVulnerable: event.groundTruthVulnerable,
  });

  classifiedByMechanism["rule-based"].push({
    assetId: event.assetId,
    scenarioId: event.scenarioId,
    tick: event.tick,
    mechanism: "rule-based",
    class: ruleBasedMechanism(event.signal),
    groundTruthVulnerable: event.groundTruthVulnerable,
  });

  classifiedByMechanism["lpa2v-cluster"].push({
    assetId: event.assetId,
    scenarioId: event.scenarioId,
    tick: event.tick,
    mechanism: "lpa2v-cluster",
    class: lpa2v(event.assetId, event.signal, asset),
    groundTruthVulnerable: event.groundTruthVulnerable,
  });
}

// ---- Tabela geral (equivalente a Figura 2 do artigo original) ----
console.log("Comparacao geral entre mecanismos\n");
const mechanisms: MechanismName[] = ["threshold", "rule-based", "lpa2v-cluster"];
const overallRows = mechanisms.map((m) => {
  const c = computeConfusion(classifiedByMechanism[m]);
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
    c.totalEscalations,
  ];
});
printTable(
  ["Mecanismo", "Precisao", "Recall", "F1", "TP", "FP", "FN", "Alertas", "Inconsist.", "Total"],
  overallRows,
);

// ---- Tabela por cenario ----
console.log("\nDetalhe por cenario (alertas emitidos por mecanismo)\n");
const scenarioRows = sim.scenarios.map((scenario) => {
  const perMechAlerts = mechanisms.map((m) => {
    const events = classifiedByMechanism[m].filter((e) => e.scenarioId === scenario.id);
    const c = computeConfusion(events);
    return `${c.alerts}a/${c.inconsistent}i`;
  });
  return [scenario.id, scenario.groundTruthNarrative, ...perMechAlerts];
});
printTable(["Cenario", "Verdade", "Threshold", "Rule-Based", "LPA2v"], scenarioRows);
console.log("(a = alertas normal/atencao/degradacao/critico, i = inconsistente)\n");

// ---- Antecipacao no cenario progressivo (equivalente ao loop Ethernet) ----
console.log("Antecipacao de deteccao — cenario 'secret-sprawl' (evidencia progressiva)\n");
const secretSprawl = sim.scenarios.find((s) => s.id === "secret-sprawl");
if (secretSprawl) {
  const leadRows = mechanisms.map((m) => {
    const events = classifiedByMechanism[m].filter((e) => e.scenarioId === "secret-sprawl");
    const lead = computeLeadTime(secretSprawl.events, events);
    return [
      m,
      lead.hardLimitTick ?? "-",
      lead.firstEscalatedTick ?? "-",
      lead.leadTicks ?? "-",
    ];
  });
  printTable(["Mecanismo", "Tick limite rigido", "1o tick >= degradacao", "Ticks de antecipacao"], leadRows);
}

// ---- Export para validacao/plote externo por terceiros ----
const outDir = new URL("../out/", import.meta.url).pathname;
writeJson(`${outDir}results.json`, {
  seed: SEED,
  scenarios: sim.scenarios.map((s) => ({
    id: s.id,
    name: s.name,
    description: s.description,
    groundTruthNarrative: s.groundTruthNarrative,
    assetCount: s.assets.length,
    eventCount: s.events.length,
  })),
  overall: Object.fromEntries(
    mechanisms.map((m) => [m, computeConfusion(classifiedByMechanism[m])]),
  ),
});

const csvRows: (string | number)[][] = [];
for (const m of mechanisms) {
  for (const e of classifiedByMechanism[m]) {
    csvRows.push([m, e.scenarioId, e.assetId, e.tick, e.class, String(e.groundTruthVulnerable)]);
  }
}
writeCsv(
  `${outDir}events.csv`,
  ["mechanism", "scenarioId", "assetId", "tick", "class", "groundTruthVulnerable"],
  csvRows,
);

console.log(`\nResultados exportados em out/results.json e out/events.csv\n`);
