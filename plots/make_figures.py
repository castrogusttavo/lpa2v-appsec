"""Gera as figuras do artigo a partir de out/results.json e out/events.csv.

Uso:
    plots/.venv/bin/python plots/make_figures.py

Le os arquivos ja exportados pelo simulador (nao reimplementa nenhuma
logica de classificacao) e escreve PDF + SVG + PNG (300dpi) em
plots/figures/, prontos para colar no artigo (LaTeX ou Word).

Paleta e especificacoes de marca seguem a skill de dataviz do projeto:
ordem categorica fixa (nunca por ranking de desempenho), uma unica
escala por eixo, grades solidas em hairline, rotulos diretos seletivos,
texto sempre em tinta neutra (nunca na cor da serie).
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
FIG_DIR = Path(__file__).resolve().parent / "figures"
FIG_DIR.mkdir(exist_ok=True)

# --- paleta (ordem categorica fixa, nunca reordenada por desempenho) ---
COLOR = {
    "threshold": "#2a78d6",  # slot 1 azul
    "rule-based": "#eb6834",  # slot 2 laranja
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
    "portfolio": "portfólio",
}
# threshold e rule-based coincidem em alguns cenarios (ex.: secret-sprawl) —
# traco e marcador distintos garantem que a linha de baixo nao desapareça.
LINESTYLE = {"threshold": "-", "rule-based": (0, (4, 2)), "lpa2v-cluster": "-"}
MARKER = {"threshold": "o", "rule-based": "s", "lpa2v-cluster": "D"}

INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID = "#e1e0d9"
SURFACE = "#fcfcfb"

# rampa ordinal de severidade (azul, claro->escuro) + cor categorica
# distinta para "inconsistente" (nao faz parte da ordem de severidade)
SEVERITY_ORDER = ["normal", "atencao", "degradacao", "critico"]
SEVERITY_RAMP = {
    "normal": "#cde2fb",
    "atencao": "#6da7ec",
    "degradacao": "#256abf",
    "critico": "#0d366b",
}
INCONSISTENT_COLOR = "#4a3aa7"  # violeta (slot 7) — estado a parte, nao ordinal

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
# Figura 1 — diagrama conceitual: threshold -> rule-based -> cluster LPA2v
# (equivalente a Fig. 1 do artigo original)
# ---------------------------------------------------------------------------
def fig_conceptual_diagram():
    from matplotlib.patches import FancyBboxPatch

    fig, ax = plt.subplots(figsize=(10, 6.4))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")
    ax.set_title(
        "Evolução dos mecanismos de decisão em triagem de AppSec",
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
            "subtitle": "Compara cada achado isoladamente\ncom um limite de severidade",
            "bullets": [
                "Simples e direto",
                "Ignora contexto de código/operacional",
                "Não trata evidências contraditórias",
                "Gera muitos falsos positivos",
            ],
            "title_ink": "#ffffff",
        },
        {
            "mech": "rule-based",
            "x0": 3.65,
            "title": "Rule-Based",
            "subtitle": "Combina exceções e condições\nexplícitas (IF-THEN)",
            "bullets": [
                "Reduz parte dos falsos positivos",
                "Regras fixas, pouco flexíveis",
                "Difícil manter com mais exceções",
                "Falha em cenários não previstos\n(WAF, scanner instável)",
            ],
            "title_ink": "#ffffff",
        },
        {
            "mech": "lpa2v-cluster",
            "x0": 7.0,
            "title": "Cluster Hierárquico\nLPA2v",
            "subtitle": "Neurônios especializados (SAST/SCA/\nDAST/contexto) + neurônio mestre +\npersistência temporal",
            "bullets": [
                "Integra múltiplas evidências",
                "Trata contradição nativamente",
                "Diferencia achado esperado de real",
                "Reduz drasticamente falsos positivos",
            ],
            "title_ink": INK_PRIMARY,
        },
    ]

    box_w, box_y0, box_h = 2.7, 1.8, 4.8
    header_h = 1.25

    for b in boxes:
        x0 = b["x0"]
        color = COLOR[b["mech"]]

        # corpo da caixa
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
        # cabecalho colorido
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
        # a base do cabecalho tem cantos arredondados no boxstyle; cobre os
        # cantos inferiores do cabecalho para ficarem retos (encontro com o corpo)
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

    # setas de evolucao entre as caixas
    arrow_labels = ["adiciona\nregras explícitas", "adiciona\ncorrelação contextual"]
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

    # faixa de beneficios do cluster LPA2v
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
        "Benefícios da abordagem LPA2v",
        ha="center",
        va="top",
        fontsize=9,
        fontweight="bold",
        color=INK_PRIMARY,
    )
    benefits = [
        "Redução drástica de falsos positivos",
        "Menos fadiga de triagem",
        "Correlação contextual de achados",
        "Identifica estados inconsistentes",
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

    save(fig, "fig1_diagrama_conceitual")


# ---------------------------------------------------------------------------
# Figura 2 — precisao / recall / F1 por mecanismo (equivalente Fig. 2 do artigo)
# ---------------------------------------------------------------------------
def fig_overall_metrics(results: dict):
    metrics = ["precision", "recall", "f1"]
    metric_labels = ["Precisão", "Recall", "F1-score"]

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
    ax.set_title("Precisão, recall e F1-score por mecanismo", fontsize=11, color=INK_PRIMARY, loc="left")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.15), ncol=3)
    save(fig, "fig2_metricas_principais")


# ---------------------------------------------------------------------------
# Figura 3 — TP / FP / FN por mecanismo (equivalente Fig. 2, "erros")
# ---------------------------------------------------------------------------
def fig_error_volume(results: dict):
    fields = ["truePositives", "falsePositives", "falseNegatives"]
    field_labels = ["Verdadeiros\npositivos", "Falsos\npositivos", "Falsos\nnegativos"]

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
    ax.set_ylabel("Eventos")
    ax.set_title("Volume de acertos e erros por mecanismo", fontsize=11, color=INK_PRIMARY, loc="left")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.18), ncol=3)
    save(fig, "fig3_volume_erros")


# ---------------------------------------------------------------------------
# Figura 4 — evolucao temporal no cenario 'secret-sprawl' (equivalente Fig. 3/4)
# ---------------------------------------------------------------------------
def fig_secret_sprawl_timeline(events: pd.DataFrame, results: dict):
    scenario = events[events["scenarioId"] == "secret-sprawl"]
    rank = {"normal": 0, "atencao": 1, "degradacao": 2, "critico": 3, "inconsistente": 1.5}

    # Tick em que a evidencia bruta cruza o limite rigido do mecanismo
    # Threshold (severidade SAST == critical OU CVSS SCA >= 9 OU DAST
    # confirmado) — mesmo valor reportado pelo `pnpm sim` no terminal.
    # Nao esta no events.csv por evento, entao fica fixo aqui; ver
    # src/metrics/leadTime.ts para a definicao exata.
    hard_limit_tick = 24

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    for mech in MECHANISMS:
        # media do rank por tick entre os 3 ativos do cenario (todos seguem o mesmo padrao)
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
        "limite rígido (evidência bruta)",
        xy=(hard_limit_tick, 1.85),
        xytext=(hard_limit_tick - 0.6, 1.85),
        fontsize=8,
        color=INK_MUTED,
        ha="right",
        va="center",
    )

    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["normal", "atenção", "degradação", "crítico"])
    ax.set_ylim(-0.2, 3.5)
    ax.set_xlabel("tick de scan")
    ax.set_title(
        "Cenário 'secret-sprawl': classificação ao longo do tempo",
        fontsize=11,
        color=INK_PRIMARY,
        loc="left",
    )
    ax.legend(frameon=False, loc="upper left")
    save(fig, "fig4_evolucao_secret_sprawl")


# ---------------------------------------------------------------------------
# Figuras 5 e 6 — mapa de calor ativo x tick, os 3 mecanismos lado a lado
# (equivalente a Fig. 5 do artigo original: distribuicao espacial)
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
        ax.set_xlabel("tick de scan")
        ax.set_yticks([])
        ax.grid(False)
        ax.set_title(MECH_LABEL[mech], fontsize=10, color=INK_PRIMARY, loc="left")

    axes[0].set_ylabel("ativo")
    fig.suptitle(
        f"Classificação por ativo × tempo — cenário '{scenario_id}'",
        fontsize=11,
        color=INK_PRIMARY,
        x=0.02,
        ha="left",
    )

    cbar = fig.colorbar(im, ax=axes, ticks=[i + 0.5 for i in range(len(class_order))], fraction=0.05, pad=0.02)
    cbar.ax.set_yticklabels(["normal", "atenção", "degradação", "crítico", "inconsistente"])
    cbar.outline.set_visible(False)
    save(fig, f"fig{fig_number}_heatmap_{scenario_id}")


# ---------------------------------------------------------------------------
# Figura 7 — alertas acumulados ao longo da simulacao (equivalente Fig. 6)
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

    ax.set_xlabel("índice do evento (ordem de geração da simulação)")
    ax.set_ylabel("alertas acumulados")
    ax.set_title("Alertas acumulados ao longo da simulação", fontsize=11, color=INK_PRIMARY, loc="left")
    ax.legend(frameon=False, loc="upper left")
    save(fig, "fig7_alertas_acumulados")


# ---------------------------------------------------------------------------
# Figura 8 — Tabela 1 (validacao com dados reais) renderizada como imagem
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
                "Combinado",
                str(combined["n"]),
                MECH_LABEL[mech],
                f"{m['precision'] * 100:.2f}%",
                f"{m['recall'] * 100:.2f}%",
                f"{m['f1'] * 100:.2f}%",
            ]
        )
        row_colors.append(COLOR["lpa2v-cluster"] if mech == "lpa2v-cluster" else "#dfe3f5")

    headers = ["Repositório", "N", "Mecanismo", "Precisão", "Recall", "F1"]

    fig, ax = plt.subplots(figsize=(7.2, 0.35 * (len(rows) + 1) + 0.5))
    ax.axis("off")
    ax.set_title(
        "Precisão, recall e F1 por repositório e combinado",
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

    save(fig, "fig8_dados_reais_tabela")


# ---------------------------------------------------------------------------
# Figura 9 — precisao/recall/F1 combinados nos dados reais (equivalente Fig. 2)
# ---------------------------------------------------------------------------
def fig_real_data_metrics(real_data: dict):
    metrics = ["precision", "recall", "f1"]
    metric_labels = ["Precisão", "Recall", "F1-score"]

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
        f"Precisão, recall e F1-score combinados — {n} achados reais em 5 repositórios",
        fontsize=10.5,
        color=INK_PRIMARY,
        loc="left",
    )
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.15), ncol=3)
    save(fig, "fig9_dados_reais_metricas")


def main():
    print(f"Lendo dados de {OUT_DIR} ...")
    results = load_results()
    events = load_events()
    real_data = load_real_data()

    print(f"Gerando figuras em {FIG_DIR} ...")
    fig_conceptual_diagram()
    fig_overall_metrics(results)
    fig_error_volume(results)
    fig_secret_sprawl_timeline(events, results)
    fig_heatmap(events, "waf-shield", 5)
    fig_heatmap(events, "flaky-scanner", 6)
    fig_cumulative_alerts(events)
    fig_real_data_table(real_data)
    fig_real_data_metrics(real_data)
    print("Concluído.")


if __name__ == "__main__":
    main()
