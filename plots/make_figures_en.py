"""Generates the English-language article figures from out/results.json and
out/events.csv — the same source data the pt-BR script (make_figures.py)
reads, so there is no reimplementation of any classification logic here,
only translated chart text for the English version of the article.

Usage:
    plots/.venv/bin/python plots/make_figures_en.py

Writes PDF + SVG + PNG (300dpi) to plots/figures_en/, ready to paste into
the English write-up. The pt-BR figures in plots/figures/ are untouched.

Palette and mark specs follow this project's dataviz guidelines: fixed
categorical order (never reordered by performance), a single scale per
axis, solid hairline grids, selective direct labels, text always in
neutral ink (never in the series color).
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "out"
REAL_DATA_DIR = ROOT / "real-data"
FIG_DIR = Path(__file__).resolve().parent / "figures_en"
FIG_DIR.mkdir(exist_ok=True)

# --- palette (fixed categorical order, never reordered by performance) ---
COLOR = {
    "threshold": "#2a78d6",  # slot 1 blue
    "rule-based": "#eb6834",  # slot 2 orange
    "lpa2v-cluster": "#1baf7a",  # slot 3 aqua
}
MECH_LABEL = {
    "threshold": "Threshold",
    "rule-based": "Rule-Based",
    "lpa2v-cluster": "LPA2v-Cluster",
}
MECHANISMS = ["threshold", "rule-based", "lpa2v-cluster"]
REPOS = ["nexo", "steel", "freecodecamp", "plane", "portfolio"]
REPO_LABEL = {
    "nexo": "nexo",
    "steel": "steel",
    "freecodecamp": "freeCodeCamp",
    "plane": "Plane",
    "portfolio": "portfolio",
}
# threshold and rule-based coincide in some scenarios (e.g. secret-sprawl) —
# distinct dash/marker styles keep the bottom line from disappearing.
LINESTYLE = {"threshold": "-", "rule-based": (0, (4, 2)), "lpa2v-cluster": "-"}
MARKER = {"threshold": "o", "rule-based": "s", "lpa2v-cluster": "D"}

INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID = "#e1e0d9"
SURFACE = "#fcfcfb"

# ordinal severity ramp (blue, light->dark) + distinct categorical color
# for "inconsistente" (not part of the severity ordering). Dict keys stay
# in the raw class values produced by the simulator (data contract), only
# the on-chart labels are translated below.
SEVERITY_ORDER = ["normal", "atencao", "degradacao", "critico"]
SEVERITY_RAMP = {
    "normal": "#cde2fb",
    "atencao": "#6da7ec",
    "degradacao": "#256abf",
    "critico": "#0d366b",
}
INCONSISTENT_COLOR = "#4a3aa7"  # violet (slot 7) — a separate state, not ordinal

plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "text.color": INK_PRIMARY,
        "axes.edgecolor": GRID,
        "axes.labelcolor": INK_SECONDARY,
        "xtick.color": INK_MUTED,
        "ytick.color": INK_MUTED,
        "axes.facecolor": SURFACE,
        "figure.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "grid.color": GRID,
        "grid.linestyle": "-",
        "grid.linewidth": 0.8,
        "axes.grid": True,
        "axes.axisbelow": True,
        "axes.spines.top": False,
        "axes.spines.right": False,
    }
)


def load_results() -> dict:
    with open(OUT_DIR / "results.json", encoding="utf-8") as f:
        return json.load(f)


def load_events() -> pd.DataFrame:
    df = pd.read_csv(OUT_DIR / "events.csv")
    df["groundTruthVulnerable"] = df["groundTruthVulnerable"].astype(str) == "True"
    return df


def load_real_data() -> dict:
    with open(REAL_DATA_DIR / "results.json", encoding="utf-8") as f:
        return json.load(f)


def save(fig, name: str) -> None:
    for ext in ("pdf", "svg", "png"):
        kwargs = {"dpi": 300} if ext == "png" else {}
        fig.savefig(FIG_DIR / f"{name}.{ext}", bbox_inches="tight", **kwargs)
    plt.close(fig)
    print(f"  {name}.{{pdf,svg,png}}")


def bar_value_labels(ax, bars, fmt="{:.0f}"):
    for bar in bars:
        h = bar.get_height()
        ax.annotate(
            fmt.format(h),
            xy=(bar.get_x() + bar.get_width() / 2, h),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8,
            color=INK_SECONDARY,
        )


# ---------------------------------------------------------------------------
# Figure 1 — conceptual diagram: threshold -> rule-based -> LPA2v cluster
# ---------------------------------------------------------------------------
def fig_conceptual_diagram():
    from matplotlib.patches import FancyBboxPatch

    fig, ax = plt.subplots(figsize=(10, 6.4))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")
    ax.set_title(
        "Evolution of decision mechanisms in AppSec triage",
        fontsize=12,
        color=INK_PRIMARY,
        loc="left",
        pad=14,
    )

    boxes = [
        {
            "mech": "threshold",
            "x0": 0.3,
            "title": "Threshold",
            "subtitle": "Compares each finding in isolation\nagainst a severity limit",
            "bullets": [
                "Simple and direct",
                "Ignores code/operational context",
                "Does not handle contradictory evidence",
                "Generates many false positives",
            ],
            "title_ink": "#ffffff",
        },
        {
            "mech": "rule-based",
            "x0": 3.65,
            "title": "Rule-Based",
            "subtitle": "Combines explicit exceptions\nand conditions (IF-THEN)",
            "bullets": [
                "Reduces part of the false positives",
                "Fixed rules, not very flexible",
                "Hard to maintain as exceptions grow",
                "Fails on unforeseen scenarios\n(WAF, unstable scanner)",
            ],
            "title_ink": "#ffffff",
        },
        {
            "mech": "lpa2v-cluster",
            "x0": 7.0,
            "title": "LPA2v\nHierarchical Cluster",
            "subtitle": "Specialized neurons (SAST/SCA/\nDAST/context) + master neuron +\ntemporal persistence",
            "bullets": [
                "Integrates multiple sources of evidence",
                "Handles contradiction natively",
                "Distinguishes expected findings from real ones",
                "Drastically reduces false positives",
            ],
            "title_ink": INK_PRIMARY,
        },
    ]

    box_w, box_y0, box_h = 2.7, 1.8, 4.8
    header_h = 1.25

    for b in boxes:
        x0 = b["x0"]
        color = COLOR[b["mech"]]

        # box body
        ax.add_patch(
            FancyBboxPatch(
                (x0, box_y0),
                box_w,
                box_h,
                boxstyle="round,pad=0,rounding_size=0.12",
                facecolor=SURFACE,
                edgecolor=color,
                linewidth=1.4,
                zorder=2,
            )
        )
        # colored header
        ax.add_patch(
            FancyBboxPatch(
                (x0, box_y0 + box_h - header_h),
                box_w,
                header_h,
                boxstyle="round,pad=0,rounding_size=0.12",
                facecolor=color,
                edgecolor=color,
                linewidth=0,
                zorder=3,
            )
        )
        # the header's base has rounded corners from boxstyle; cover its
        # bottom corners so they're square (where it meets the body)
        ax.add_patch(
            plt.Rectangle(
                (x0, box_y0 + box_h - header_h),
                box_w,
                header_h * 0.4,
                facecolor=color,
                edgecolor="none",
                zorder=2.5,
            )
        )

        ax.text(
            x0 + box_w / 2,
            box_y0 + box_h - header_h / 2,
            b["title"],
            ha="center",
            va="center",
            fontsize=10.5,
            fontweight="bold",
            color=b["title_ink"],
            zorder=4,
            linespacing=1.3,
        )

        ax.text(
            x0 + box_w / 2,
            box_y0 + box_h - header_h - 0.55,
            b["subtitle"],
            ha="center",
            va="top",
            fontsize=8,
            color=INK_SECONDARY,
            zorder=4,
            linespacing=1.4,
        )

        bullet_y = box_y0 + box_h - header_h - 1.55
        for bullet in b["bullets"]:
            ax.text(
                x0 + 0.18,
                bullet_y,
                f"• {bullet}",
                ha="left",
                va="top",
                fontsize=7.6,
                color=INK_PRIMARY,
                zorder=4,
                linespacing=1.3,
            )
            bullet_y -= 0.30 * (bullet.count("\n") + 1) + 0.28

    # evolution arrows between the boxes
    arrow_labels = ["adds\nexplicit rules", "adds\ncontextual correlation"]
    for i, label in enumerate(arrow_labels):
        x_from = boxes[i]["x0"] + box_w
        x_to = boxes[i + 1]["x0"]
        y_mid = box_y0 + box_h / 2
        ax.annotate(
            "",
            xy=(x_to, y_mid),
            xytext=(x_from, y_mid),
            arrowprops=dict(arrowstyle="-|>", color=INK_MUTED, linewidth=1.6),
            zorder=1,
        )
        ax.text(
            (x_from + x_to) / 2,
            y_mid + 0.28,
            label,
            ha="center",
            va="bottom",
            fontsize=7.2,
            color=INK_MUTED,
            linespacing=1.2,
        )

    # LPA2v cluster benefits banner
    banner_y0, banner_h = 0.15, 1.35
    ax.add_patch(
        FancyBboxPatch(
            (0.3, banner_y0),
            9.4,
            banner_h,
            boxstyle="round,pad=0,rounding_size=0.12",
            facecolor="#eef0fb",
            edgecolor=COLOR["lpa2v-cluster"],
            linewidth=1.0,
            zorder=1,
        )
    )
    ax.text(
        5.0,
        banner_y0 + banner_h - 0.28,
        "Benefits of the LPA2v approach",
        ha="center",
        va="top",
        fontsize=9,
        fontweight="bold",
        color=INK_PRIMARY,
    )
    benefits = [
        "Drastic reduction in false positives",
        "Less triage fatigue",
        "Contextual correlation of findings",
        "Identifies inconsistent states",
    ]
    n = len(benefits)
    slot_w = 9.4 / n
    for i, benefit in enumerate(benefits):
        cx = 0.3 + slot_w * (i + 0.5)
        ax.text(
            cx,
            banner_y0 + 0.42,
            benefit,
            ha="center",
            va="center",
            fontsize=7.2,
            color=INK_SECONDARY,
            linespacing=1.3,
            wrap=True,
        )

    save(fig, "fig1_conceptual_diagram")


# ---------------------------------------------------------------------------
# Figure 2 — precision / recall / F1 by mechanism
# ---------------------------------------------------------------------------
def fig_overall_metrics(results: dict):
    metrics = ["precision", "recall", "f1"]
    metric_labels = ["Precision", "Recall", "F1-score"]

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    n_mech = len(MECHANISMS)
    width = 0.24
    x = range(len(metrics))

    for i, mech in enumerate(MECHANISMS):
        vals = [results["overall"][mech][m] * 100 for m in metrics]
        offset = (i - (n_mech - 1) / 2) * width
        bars = ax.bar(
            [xi + offset for xi in x],
            vals,
            width=width * 0.9,
            color=COLOR[mech],
            edgecolor=INK_PRIMARY,
            linewidth=0.6,
            label=MECH_LABEL[mech],
        )
        bar_value_labels(ax, bars, fmt="{:.1f}")

    ax.set_xticks(list(x))
    ax.set_xticklabels(metric_labels)
    ax.set_ylabel("%")
    ax.set_ylim(0, 110)
    ax.yaxis.set_major_locator(mticker.MultipleLocator(20))
    ax.set_title("Precision, recall, and F1-score by mechanism", fontsize=11, color=INK_PRIMARY, loc="left")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.15), ncol=3)
    save(fig, "fig2_key_metrics")


# ---------------------------------------------------------------------------
# Figure 3 — TP / FP / FN by mechanism
# ---------------------------------------------------------------------------
def fig_error_volume(results: dict):
    fields = ["truePositives", "falsePositives", "falseNegatives"]
    field_labels = ["True\npositives", "False\npositives", "False\nnegatives"]

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    n_mech = len(MECHANISMS)
    width = 0.24
    x = range(len(fields))

    for i, mech in enumerate(MECHANISMS):
        vals = [results["overall"][mech][f] for f in fields]
        offset = (i - (n_mech - 1) / 2) * width
        bars = ax.bar(
            [xi + offset for xi in x],
            vals,
            width=width * 0.9,
            color=COLOR[mech],
            edgecolor=INK_PRIMARY,
            linewidth=0.6,
            label=MECH_LABEL[mech],
        )
        bar_value_labels(ax, bars, fmt="{:.0f}")

    ax.set_xticks(list(x))
    ax.set_xticklabels(field_labels)
    ax.set_ylabel("Events")
    ax.set_title("Volume of true positives, false positives, and false negatives by mechanism", fontsize=11, color=INK_PRIMARY, loc="left")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.18), ncol=3)
    save(fig, "fig3_error_volume")


# ---------------------------------------------------------------------------
# Figure 4 — temporal evolution in the 'secret-sprawl' scenario
# ---------------------------------------------------------------------------
def fig_secret_sprawl_timeline(events: pd.DataFrame, results: dict):
    scenario = events[events["scenarioId"] == "secret-sprawl"]
    rank = {"normal": 0, "atencao": 1, "degradacao": 2, "critico": 3, "inconsistente": 1.5}

    # Tick at which the raw evidence crosses the Threshold mechanism's hard
    # limit (SAST severity == critical OR SCA CVSS >= 9 OR DAST confirmed)
    # — same value reported by `pnpm sim` in the terminal. Not present in
    # events.csv per event, so it's hardcoded here; see
    # src/metrics/leadTime.ts for the exact definition.
    hard_limit_tick = 24

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    for mech in MECHANISMS:
        # mean rank per tick across the scenario's 3 assets (all follow the same pattern)
        sub_mean = (
            scenario[scenario["mechanism"] == mech]
            .assign(rank=lambda d: d["class"].map(rank))
            .groupby("tick")["rank"]
            .mean()
        )
        ax.plot(
            sub_mean.index,
            sub_mean.values,
            color=COLOR[mech],
            linewidth=2,
            linestyle=LINESTYLE[mech],
            solid_capstyle="round",
            marker=MARKER[mech],
            markersize=4,
            markevery=2,
            label=MECH_LABEL[mech],
        )

    ax.axvline(hard_limit_tick, color=INK_MUTED, linestyle="--", linewidth=1)
    ax.annotate(
        "hard limit (raw evidence)",
        xy=(hard_limit_tick, 1.85),
        xytext=(hard_limit_tick - 0.6, 1.85),
        fontsize=8,
        color=INK_MUTED,
        ha="right",
        va="center",
    )

    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["normal", "attention", "degradation", "critical"])
    ax.set_ylim(-0.2, 3.5)
    ax.set_xlabel("scan tick")
    ax.set_title(
        "Scenario 'secret-sprawl': classification over time",
        fontsize=11,
        color=INK_PRIMARY,
        loc="left",
    )
    ax.legend(frameon=False, loc="upper left")
    save(fig, "fig4_secret_sprawl_evolution")


# ---------------------------------------------------------------------------
# Figures 5 and 6 — asset x tick heatmap, the 3 mechanisms side by side
# (spatial distribution)
# ---------------------------------------------------------------------------
def fig_heatmap(events: pd.DataFrame, scenario_id: str, fig_number: int):
    from matplotlib.colors import ListedColormap, BoundaryNorm

    class_order = ["normal", "atencao", "degradacao", "critico", "inconsistente"]
    class_to_idx = {c: i for i, c in enumerate(class_order)}
    colors = [
        SEVERITY_RAMP["normal"],
        SEVERITY_RAMP["atencao"],
        SEVERITY_RAMP["degradacao"],
        SEVERITY_RAMP["critico"],
        INCONSISTENT_COLOR,
    ]
    cmap = ListedColormap(colors)
    norm = BoundaryNorm(range(len(class_order) + 1), cmap.N)

    fig, axes = plt.subplots(1, 3, figsize=(9.6, 3.4), sharey=True)
    im = None
    for ax, mech in zip(axes, MECHANISMS):
        sub = events[
            (events["scenarioId"] == scenario_id) & (events["mechanism"] == mech)
        ].copy()
        sub["idx"] = sub["class"].map(class_to_idx)
        pivot = sub.pivot(index="assetId", columns="tick", values="idx")
        im = ax.imshow(pivot.values, aspect="auto", cmap=cmap, norm=norm)
        ax.set_xlabel("scan tick")
        ax.set_yticks([])
        ax.grid(False)
        ax.set_title(MECH_LABEL[mech], fontsize=10, color=INK_PRIMARY, loc="left")

    axes[0].set_ylabel("asset")
    fig.suptitle(
        f"Classification by asset × time — scenario '{scenario_id}'",
        fontsize=11,
        color=INK_PRIMARY,
        x=0.02,
        ha="left",
    )

    cbar = fig.colorbar(im, ax=axes, ticks=[i + 0.5 for i in range(len(class_order))], fraction=0.05, pad=0.02)
    cbar.ax.set_yticklabels(["normal", "attention", "degradation", "critical", "inconsistent"])
    cbar.outline.set_visible(False)
    save(fig, f"fig{fig_number}_heatmap_{scenario_id}")


# ---------------------------------------------------------------------------
# Figure 7 — cumulative alerts over the course of the simulation
# ---------------------------------------------------------------------------
def fig_cumulative_alerts(events: pd.DataFrame):
    fig, ax = plt.subplots(figsize=(6.4, 3.6))

    for mech in MECHANISMS:
        sub = events[events["mechanism"] == mech].reset_index(drop=True)
        is_alert = ~sub["class"].isin(["normal", "inconsistente"])
        cumulative = is_alert.cumsum()
        ax.plot(
            range(len(cumulative)),
            cumulative,
            color=COLOR[mech],
            linewidth=2,
            linestyle=LINESTYLE[mech],
            solid_capstyle="round",
            label=MECH_LABEL[mech],
        )

    ax.set_xlabel("event index (simulation generation order)")
    ax.set_ylabel("cumulative alerts")
    ax.set_title("Cumulative alerts over the course of the simulation", fontsize=11, color=INK_PRIMARY, loc="left")
    ax.legend(frameon=False, loc="upper left")
    save(fig, "fig7_cumulative_alerts")


# ---------------------------------------------------------------------------
# Figure 8 — Table 1 (real-data validation) rendered as an image
# ---------------------------------------------------------------------------
def fig_real_data_table(real_data: dict):
    rows = []
    row_colors = []
    for repo in REPOS:
        entry = real_data["perRepo"][repo]
        n = entry["n"]
        for mech in MECHANISMS:
            m = entry["mechanisms"][mech]
            rows.append(
                [
                    REPO_LABEL[repo],
                    str(n),
                    MECH_LABEL[mech],
                    f"{m['precision'] * 100:.2f}%",
                    f"{m['recall'] * 100:.2f}%",
                    f"{m['f1'] * 100:.2f}%",
                ]
            )
            row_colors.append("#eafaf2" if mech == "lpa2v-cluster" else SURFACE)

    combined = real_data["combined"]
    for mech in MECHANISMS:
        m = combined["mechanisms"][mech]
        rows.append(
            [
                "Combined",
                str(combined["n"]),
                MECH_LABEL[mech],
                f"{m['precision'] * 100:.2f}%",
                f"{m['recall'] * 100:.2f}%",
                f"{m['f1'] * 100:.2f}%",
            ]
        )
        row_colors.append(COLOR["lpa2v-cluster"] if mech == "lpa2v-cluster" else "#dfe3f5")

    headers = ["Repository", "N", "Mechanism", "Precision", "Recall", "F1"]

    fig, ax = plt.subplots(figsize=(7.2, 0.35 * (len(rows) + 1) + 0.5))
    ax.axis("off")
    ax.set_title(
        "Precision, recall, and F1 by repository and combined",
        fontsize=11,
        color=INK_PRIMARY,
        loc="left",
        pad=10,
    )

    table = ax.table(cellText=rows, colLabels=headers, cellLoc="center", loc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(8.5)
    table.scale(1, 1.55)

    n_cols = len(headers)
    for (r, c), cell in table.get_celld().items():
        cell.set_edgecolor(GRID)
        cell.set_linewidth(0.8)
        if r == 0:
            cell.set_facecolor(INK_PRIMARY)
            cell.get_text().set_color("#ffffff")
            cell.get_text().set_fontweight("bold")
        else:
            cell.set_facecolor(row_colors[r - 1])
            is_combined_lpa2v = r == len(rows) and row_colors[r - 1] == COLOR["lpa2v-cluster"]
            if is_combined_lpa2v:
                cell.get_text().set_color("#ffffff" if c != 0 else INK_PRIMARY)
                cell.get_text().set_fontweight("bold")
            elif row_colors[r - 1] == "#dfe3f5":
                cell.get_text().set_fontweight("bold")

    save(fig, "fig8_real_data_table")


# ---------------------------------------------------------------------------
# Figure 9 — combined precision/recall/F1 on real data
# ---------------------------------------------------------------------------
def fig_real_data_metrics(real_data: dict):
    metrics = ["precision", "recall", "f1"]
    metric_labels = ["Precision", "Recall", "F1-score"]

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    n_mech = len(MECHANISMS)
    width = 0.24
    x = range(len(metrics))

    for i, mech in enumerate(MECHANISMS):
        vals = [real_data["combined"]["mechanisms"][mech][m] * 100 for m in metrics]
        offset = (i - (n_mech - 1) / 2) * width
        bars = ax.bar(
            [xi + offset for xi in x],
            vals,
            width=width * 0.9,
            color=COLOR[mech],
            edgecolor=INK_PRIMARY,
            linewidth=0.6,
            label=MECH_LABEL[mech],
        )
        bar_value_labels(ax, bars, fmt="{:.1f}")

    ax.set_xticks(list(x))
    ax.set_xticklabels(metric_labels)
    ax.set_ylabel("%")
    ax.set_ylim(0, 110)
    ax.yaxis.set_major_locator(mticker.MultipleLocator(20))
    n = real_data["combined"]["n"]
    ax.set_title(
        f"Combined precision, recall, and F1-score — {n} real findings across 5 repositories",
        fontsize=10.5,
        color=INK_PRIMARY,
        loc="left",
    )
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.15), ncol=3)
    save(fig, "fig9_real_data_metrics")


def main():
    print(f"Reading data from {OUT_DIR} ...")
    results = load_results()
    events = load_events()
    real_data = load_real_data()

    print(f"Generating figures in {FIG_DIR} ...")
    fig_conceptual_diagram()
    fig_overall_metrics(results)
    fig_error_volume(results)
    fig_secret_sprawl_timeline(events, results)
    fig_heatmap(events, "waf-shield", 5)
    fig_heatmap(events, "flaky-scanner", 6)
    fig_cumulative_alerts(events)
    fig_real_data_table(real_data)
    fig_real_data_metrics(real_data)
    print("Done.")


if __name__ == "__main__":
    main()
