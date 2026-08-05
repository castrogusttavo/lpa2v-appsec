import type { ParaClass } from "../core/types.js";

// Persistencia temporal: o artigo original aplica "persistencia temporal de
// cinco minutos antes de emitir a classe final". Aqui cada "tick" representa
// um ciclo de scan (nao um minuto), e o cluster so deixa uma severidade
// subir para degradacao/critico depois que ela se sustenta por
// `windowSize` ticks consecutivos. Isso tem dois efeitos, ambos
// intencionais e visiveis nos cenarios simulados:
//   1. Evita que um achado isolado e instavel (ex.: scanner instavel)
//      dispare direto um alerta critico.
//   2. Cria um atraso de "aquecimento": a severidade so escala depois de
//      confirmada a tendencia, o que produz o efeito de antecipacao (o grau
//      de certeza sobe visivelmente antes da classe final acompanhar).

const RANK: Record<Exclude<ParaClass, "inconsistente">, number> = {
  normal: 0,
  atencao: 1,
  degradacao: 2,
  critico: 3,
};

const RANK_TO_CLASS: Exclude<ParaClass, "inconsistente">[] = [
  "normal",
  "atencao",
  "degradacao",
  "critico",
];

export class PersistenceTracker {
  private readonly windows = new Map<string, number[]>();

  constructor(private readonly windowSize: number = 3) {}

  apply(assetId: string, rawClass: ParaClass): ParaClass {
    if (rawClass === "inconsistente") {
      // Contradicao e, em si, o resultado informativo — nao ha razao para
      // atrasar o report, e o tick nao entra na janela de severidade.
      return "inconsistente";
    }

    const rank = RANK[rawClass];
    const hist = this.windows.get(assetId) ?? [];
    hist.push(rank);
    if (hist.length > this.windowSize) hist.shift();
    this.windows.set(assetId, hist);

    const warmingUp = hist.length < this.windowSize;
    const sustainedRank = warmingUp
      ? Math.min(rank, RANK.atencao)
      : Math.min(...hist);

    const finalClass = RANK_TO_CLASS[sustainedRank];
    if (finalClass === undefined) {
      throw new Error(`Rank invalido: ${sustainedRank}`);
    }
    return finalClass;
  }

  reset(): void {
    this.windows.clear();
  }
}
