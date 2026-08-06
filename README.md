# LPA2v-AppSec

A simulator for a **hierarchical cluster of LPA2v paraconsistent neurons**
applied to application-security finding triage (SAST/SCA/DAST), focused on
**false-positive reduction** and **contextual correlation**.

The architecture is grounded in two-valued paraconsistent annotated logic
(da Costa, 1974; Abe, 2015): instead of forcing a binary true/false verdict
on every finding, each source of evidence contributes a **favorable**
(`μ`) and an **unfavorable** (`λ`) degree, and both are allowed to coexist
— including when they contradict each other. This project designs and
validates a specific architecture on top of that theory (specialized
domain neurons, a master neuron with two separate aggregation paths, and
temporal persistence) applied to triaging findings from SAST, SCA, and DAST
tools, correlating them with code context and operational context to
decide what actually deserves to become an alert.

> **This is a simulator with synthetic data**, not a tool running against
> live scanners in production. The goal is to demonstrate and let third
> parties reproduce/validate the architecture and its decision logic — not
> to measure production performance. See [Limitations](#limitations). A
> separate validation against 559 real findings from 5 applications is
> also included — see [Real-data validation](#real-data-validation).

## Why paraconsistent logic here

AppSec tools frequently disagree with each other, and that disagreement is
information, not noise to be discarded. A SAST scanner might flag an
endpoint as missing authentication while a DAST scanner tries to exploit
it at runtime and gets blocked by a WAF — classical logic forces a binary
decision ("it's vulnerable" or "it isn't") and discards one of the two
signals. LPA2v doesn't force that choice: it represents **favorable**
(`μ`) and **unfavorable** (`λ`) evidence separately and lets both coexist.

For a proposition P ("this finding is a real vulnerability"):

```
GC  = μ - λ        certainty degree      (∈ [-1, 1])
GCT = μ + λ - 1     contradiction degree  (∈ [-1, 1])
```

High, positive `GC` → evidence strongly points to "it's real". Low/negative
`GC` → points to "it isn't real" (or there's no evidence). High `GCT` → `μ`
and `λ` are **both** high at once: genuine contradiction, not a tie to be
broken — it should become an **inconsistente** state, flagged for human
review, instead of a forced verdict.

## Architecture

```
raw signal (SAST, SCA, DAST, code context, operational context)
        │
        ▼
domain neurons (one per source) ── each estimates (μ, λ)
        │
        ▼
master neuron ── TWO aggregations, not one:
   • consensus    = weighted mean of μ and λ across domains
                     → drives the normal/atencao/degradacao/critico ranking
   • contradiction = largest μ across the PRIMARY DETECTORS (SAST/SCA/DAST)
                      vs. largest λ across them (may come from different
                      detectors) → decides whether the state is "inconsistente"
        │
        ▼
temporal persistence (N-scan window) ── prevents an isolated spike
        │                                 or a flaky scanner from firing
        ▼                                 an alert outright
final class: normal | atencao | degradacao | critico | inconsistente
```

**Why two aggregations instead of one?** Tested during this project's
calibration: if you aggregate μ and λ by a simple weighted mean across
*all* domains, a real contradiction between two specific detectors (e.g.
SAST shouts "yes", DAST shouts "no") gets **diluted by the mean** of the
other, neutral domains and never triggers a high `GCT` — the exact
opposite of what paraconsistent logic should do. That's why contradiction
detection uses the extremes across the primary detectors, while the
weighted mean is reserved for ranking severity when there's no conflict.
Code/operational context is deliberately left out of the contradiction
calculation: it's explanatory metadata (why the finding showed up), not
"one more vote on whether a vulnerability exists" — when context explains
a finding (e.g. an authorized maintenance window), the correct outcome is
to suppress the severity, not to open a human-review case.

## The 12 simulated scenarios

Each scenario generates synthetic events (asset × scan tick) with a ground
truth (`groundTruthVulnerable`) known to the simulator but invisible to the
three mechanisms being evaluated:

1. **dep-bump** — a dependency migration produces SCA noise with no real exploitation.
2. **waf-shield** — SAST flags missing auth; DAST tries to exploit it and gets blocked. Contradictory on purpose.
3. **secret-sprawl** — a secret leak with weak evidence early on, escalating over time.
4. **pentest-window** — real DAST findings during an authorized penetration test.
5. **staging-noise** — recurring SAST findings in a low-traffic environment.
6. **flaky-scanner** — an intermittent SAST finding caused by the scanner's own instability.
7. **confirmed-rce** — SAST + SCA + DAST agree: a real critical RCE, public-facing, no auth.
8. **confirmed-sqli** — SAST + DAST agree on a real, exploitable SQL injection.
9. **deprecated-module** — persistent findings in a deprecated, non-public, unreachable module.
10. **test-fixture** — findings on example credentials/payloads used only in tests.
11. **silent-supply-chain** — a dynamically-loaded dependency with an active exploit; only SCA sees it.
12. **internal-ambiguity** — moderate findings in a service reachable only via an internal network.

## Running it

```bash
pnpm install
pnpm sim        # runs the simulation and prints the comparison table
pnpm test       # unit tests for the paraconsistent core
pnpm typecheck
```

`npm`/`yarn` also work (`npm install && npm run sim`) — the project doesn't
depend on any pnpm-exclusive feature, and results are identical across
package managers (same seed, same output).

`pnpm sim` accepts an optional seed (`pnpm sim -- 123`) — the same seed
always produces the same simulation, so third parties can reproduce the
exact same numbers. Full per-event results are exported to
`out/results.json` and `out/events.csv`.

## Figures

The figures are generated by a separate Python script in `plots/`, which
only reads the files already exported by `pnpm sim` — it doesn't
reimplement any classification logic. Run the simulation at least once
first.

```bash
python3 -m venv plots/.venv
plots/.venv/bin/pip install -r plots/requirements.txt
plots/.venv/bin/python plots/make_figures.py
```

Chart text (titles, axis labels, legends) is in Portuguese (pt-BR): these
are the exact figures used in this project's write-up. Generates, under
`plots/figures/` (PDF + SVG + PNG at 300dpi):

- `fig1_diagrama_conceitual` — evolution from threshold → rule-based → LPA2v hierarchical cluster
- `fig2_metricas_principais` — precision/recall/F1 by mechanism
- `fig3_volume_erros` — true positives, false positives, false negatives
- `fig4_evolucao_secret_sprawl` — classification over time in the progressive scenario
- `fig5_heatmap_waf-shield` and `fig6_heatmap_flaky-scanner` — the 3 mechanisms side by side (same color scale), showing an inconsistent state vs. scattered noise
- `fig7_alertas_acumulados` — cumulative alerts over the course of the simulation
- `fig8_dados_reais_tabela` and `fig9_dados_reais_metricas` — real-data validation results (see below)

Palette and mark specs (fixed categorical order, a single scale per axis,
solid grids, selective direct labels) follow a colorblind-safety-validated
data-viz methodology.

## Results (default seed = 42)

```
Cenarios: 12 | Ativos: 206 | Eventos totais: 3005

| Mecanismo     | Precisao | Recall | F1     | TP  | FP   | FN  | Alertas | Inconsist. | Total |
| ------------- | -------- | ------ | ------ | --- | ---- | --- | ------- | ---------- | ----- |
| threshold     | 8.01%    | 86.80% | 14.66% | 217 | 2493 | 33  | 2710    | 0          | 2710  |
| rule-based    | 10.41%   | 86.80% | 18.59% | 217 | 1868 | 33  | 2085    | 0          | 2085  |
| lpa2v-cluster | 100.00%  | 65.60% | 79.23% | 164 | 0    | 86  | 164     | 300        | 464   |
```

*(exact numbers may vary slightly by seed/version — run `pnpm sim` for
current values; the ones above are from a reference run.)*

Honest reading of these numbers:

- **False positives: 2493 (threshold) → 1868 (rule-based) → 0
  (LPA2v-cluster).** This is the central result: contextual correlation
  eliminates excess alarms, not just randomly suppresses alerts.
- **Recall dropped from 86.8% to 65.6%.** This is expected and
  intentional: three of the twelve scenarios (`secret-sprawl`,
  `silent-supply-chain`, and the temporal-persistence warm-up in
  `confirmed-rce`/`confirmed-sqli`) were specifically designed to be hard
  — weak evidence, from a single domain, or in the first few ticks before
  the persistence window fills up. The cluster still catches most of these
  (including the silent supply-chain scenario, which no fixed-rule
  mechanism would see selectively), but late or only partially.
- **300 events in the `waf-shield` scenario were correctly routed to
  "inconsistente"**, neither normal nor critical — exactly the behavior
  that threshold and rule-based are structurally unable to express.
- **Detection anticipation (`secret-sprawl` scenario) did not show a
  lead-time gain in this calibration**: the cluster landed ~4 ticks
  *behind* the raw threshold in this specific scenario, because it
  requires corroboration across detectors plus sustained persistence
  before escalating past "atencao" — a deliberate trade of speed for
  classification reliability when a single domain (SAST) carries most of
  the evidence. Reporting this as obtained, rather than recalibrating
  until it "works," is intentional: the goal of this repository is to
  enable third-party validation, not to sell a result.

## Real-data validation

Beyond the synthetic simulation, the same hierarchical LPA2v cluster —
with no weight or threshold changes — was applied to real SAST/SCA/DAST
findings collected from five applications: two SaaS project-management
platforms, two large open-source projects, and a personal portfolio site.
Semgrep, Snyk, and OWASP ZAP were run locally against each application.
After deduplicating repeated SCA findings across multiple dependency
manifests, 559 distinct findings were collected and labeled by
AI-assisted human review (not by the tools' own self-reported severity,
which would make the study circular).

```
| Mecanismo     | Precisao | Recall  | F1     | TP  | FP  | FN | Alertas | Inconsist. |
| ------------- | -------- | ------- | ------ | --- | --- | -- | ------- | ---------- |
| threshold     | 31.66%   | 100.00% | 48.10% | 177 | 382 | 0  | 559     | 0          |
| rule-based    | 34.17%   | 100.00% | 50.94% | 177 | 341 | 0  | 518     | 0          |
| lpa2v-cluster | 86.84%   | 74.58%  | 80.24% | 132 | 20  | 45 | 152     | 0          |
```

With no recalibration, the cluster reached 86.84% precision and 74.58%
recall on the combined set. The weakest point is recall on one of the five
repositories (33.33%, missing 8 of 12 real positives there) — diagnosed as
a single evidence pattern (a moderate-severity finding from a single
domain) sitting right at the classifier's boundary, the same structural
issue as a marginal miss found elsewhere in the same validation (a
CVSS-7.0 finding landing at a certainty degree of 0.14 against a 0.15
threshold). Labeling rigor is not uniform across the five repositories —
disclosed explicitly as a limitation, not hidden.

## Limitations

- **Synthetic data, not real findings (for the simulation study).** The
  scenarios were designed to illustrate behavior categories (contradiction,
  explanatory context, progressive evidence, hard recall cases), not to
  replicate the statistical distribution of real Semgrep/Snyk/ZAP findings.
  The real-data validation above addresses this directly, on a smaller
  sample (559 findings).
- **Weights and thresholds were calibrated by hand** during this
  simulator's development (see `DEFAULT_WEIGHTS` in
  `src/cluster/masterNeuron.ts` and `DEFAULT_THRESHOLDS` in
  `src/core/paraconsistent.ts`), not learned from labeled data. Adaptive
  calibration from the 559 labeled real findings gathered in this project
  is a natural next step.
- **Temporal persistence uses "ticks" (scan cycles), not minutes.** The
  default value (3 ticks) is a parameter, not a theoretical constant.
- Results should be read as architecture validation in a simulated/limited
  environment — not as an operational performance benchmark for a real
  AppSec pipeline at scale.

## Code structure

```
src/core/           domain types + LPA2v core (μ, λ, GC, GCT, classification)
src/neurons/         one neuron per evidence source (SAST, SCA, DAST, code context, operational context)
src/cluster/         master neuron (consensus + contradiction) and temporal persistence
src/mechanisms/       the three mechanisms compared: threshold, rule-based, lpa2v-cluster
src/simulator/        asset generator and the 12 synthetic scenarios
src/metrics/          confusion matrix, precision/recall/F1, detection anticipation
src/report/            terminal table printing + JSON/CSV export
src/realdata/          adapters that normalize real Semgrep/Snyk/ZAP output
scripts/run-simulation.ts       synthetic-study entry point (`pnpm sim`)
scripts/prepare-real-findings.ts   builds the real-findings labeling spreadsheet
scripts/run-real-findings.ts       runs the three mechanisms against labeled real findings
tests/                unit tests for the paraconsistent core
```

## References

- N. C. A. da Costa, "On the theory of inconsistent formal systems," *Notre
  Dame Journal of Formal Logic*, vol. 15, no. 4, pp. 497–510, 1974.
- J. M. Abe (Ed.), *Paraconsistent Intelligent-Based Systems: New Trends in
  the Applications of Paraconsistency*, Springer, 2015.
- National Institute of Standards and Technology, *NIST Special
  Publication 800-218: Secure Software Development Framework (SSDF)
  Version 1.1*, Feb. 2022.
- S. Tariq, M. Baruwal Chhetri, S. Nepal, and C. Paris, "Alert Fatigue in
  Security Operations Centres: Research Challenges and Opportunities,"
  *ACM Computing Surveys*, vol. 57, no. 9, art. 224, Apr. 2025.

## License

MIT.
