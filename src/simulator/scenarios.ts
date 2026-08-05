import type { Asset, SimEvent } from "../core/types.js";
import type { Rng } from "../core/rng.js";
import { randBool, randRange } from "../core/rng.js";
import { makeAssets } from "./asset.js";
import { buildSignal, lerp } from "./signal.js";

export interface ScenarioResult {
  id: string;
  name: string;
  description: string;
  /** Cenario representa uma vulnerabilidade real (usado so para narrativa/relatorio). */
  groundTruthNarrative: "positivo" | "negativo" | "misto";
  assets: Asset[];
  events: SimEvent[];
}

type ScenarioFn = (rng: Rng) => ScenarioResult;

function pushEvents(
  events: SimEvent[],
  scenarioId: string,
  assets: Asset[],
  ticks: number,
  build: (asset: Asset, assetIndex: number, tick: number) => { signal: ReturnType<typeof buildSignal>; groundTruth: boolean },
): void {
  for (let ai = 0; ai < assets.length; ai++) {
    const asset = assets[ai];
    if (!asset) continue;
    for (let tick = 0; tick < ticks; tick++) {
      const { signal, groundTruth } = build(asset, ai, tick);
      events.push({
        assetId: asset.id,
        scenarioId,
        tick,
        signal,
        groundTruthVulnerable: groundTruth,
      });
    }
  }
}

// 1. Backup/migracao legitima: pico de dependencias durante janela de migracao,
//    sem exploracao real. Equivalente ao "backup autorizado" do artigo original.
const dependencyBumpNoise: ScenarioFn = (rng) => {
  const assets = makeAssets("dep-bump", 40);
  const events: SimEvent[] = [];
  pushEvents(events, "dep-bump", assets, 10, () => ({
    signal: buildSignal({
      sca: {
        hit: true,
        cvss: randRange(rng, 4, 6.5),
        patchAvailable: null,
        exploitMaturity: "none",
      },
    }),
    groundTruth: false,
  }));
  return {
    id: "dep-bump",
    name: "Migração de dependências (ruído esperado)",
    description:
      "Snyk aponta versões novas/transitórias durante janela de migração planejada. Nenhuma exploração real.",
    groundTruthNarrative: "negativo",
    assets,
    events,
  };
};

// 2. Endpoint protegido por WAF: SAST acusa falta de auth, DAST tenta explorar
//    e e bloqueado, mas outros sinais (ex.: resposta de health-check) seguem OK.
//    Evidencia favoravel e desfavoravel fortes ao mesmo tempo -> inconsistente.
const wafShieldedEndpoint: ScenarioFn = (rng) => {
  const assets = makeAssets("waf-shield", 15, { publicFacing: true, hasAuthMiddleware: false });
  const events: SimEvent[] = [];
  pushEvents(events, "waf-shield", assets, 20, () => ({
    signal: buildSignal({
      sast: { hit: true, severity: "high", confidence: "high", reachable: true },
      dast: { hit: true, confirmed: false },
    }),
    groundTruth: false,
  }));
  return {
    id: "waf-shield",
    name: "Endpoint protegido por WAF",
    description:
      "SAST acusa falta de autenticação; DAST tenta explorar e é bloqueado em runtime (WAF). Evidência contraditória — deve ser tratada como inconsistente, não como falha confirmada.",
    groundTruthNarrative: "negativo",
    assets,
    events,
  };
};

// 3. Vazamento de segredo progressivo: evidencia fraca no inicio, escalando
//    para critica — equivalente ao loop Ethernet progressivo do artigo.
const secretSprawlProgressive: ScenarioFn = (rng) => {
  const assets = makeAssets("secret-sprawl", 3, { publicFacing: true, hasAuthMiddleware: true });
  const events: SimEvent[] = [];
  const ticks = 30;
  pushEvents(events, "secret-sprawl", assets, ticks, (_asset, _ai, tick) => {
    if (tick < 3) {
      return { signal: buildSignal(), groundTruth: true };
    }
    const sastSeverity =
      tick < 10 ? "low" : tick < 17 ? "medium" : tick < 24 ? "high" : "critical";
    const sastConfidence = tick < 15 ? "medium" : "high";
    const scaActive = tick >= 12;
    const cvss = scaActive ? lerp(5, 8.5, (tick - 12) / 12) : null;
    const exploitMaturity = tick >= 26 ? "active" : tick >= 18 ? "poc" : "none";
    return {
      signal: buildSignal({
        sast: { hit: true, severity: sastSeverity, confidence: sastConfidence, reachable: true },
        sca: scaActive
          ? { hit: true, cvss, patchAvailable: false, exploitMaturity }
          : undefined,
      }),
      groundTruth: true,
    };
  });
  return {
    id: "secret-sprawl",
    name: "Vazamento de segredo progressivo",
    description:
      "Um segredo exposto é redescoberto em cada vez mais arquivos ao longo dos scans. A evidência é real desde o início, mas fraca — só se torna óbvia tardiamente.",
    groundTruthNarrative: "positivo",
    assets,
    events,
  };
};

// 4. Janela de pentest autorizado: DAST dispara varios achados esperados.
const pentestWindow: ScenarioFn = (rng) => {
  const assets = makeAssets("pentest-window", 25, { publicFacing: true, hasAuthMiddleware: true });
  const events: SimEvent[] = [];
  pushEvents(events, "pentest-window", assets, 15, () => ({
    signal: buildSignal({
      dast: { hit: true, confirmed: true },
      opContext: { maintenanceOrPentestWindow: true },
    }),
    groundTruth: false,
  }));
  return {
    id: "pentest-window",
    name: "Janela de pentest autorizado",
    description:
      "Testes de invasão autorizados geram achados DAST reais tecnicamente, mas esperados e sem risco não mitigado — contexto operacional deve suprimir o alarme.",
    groundTruthNarrative: "negativo",
    assets,
    events,
  };
};

// 5. Ruido de staging com baixo trafego: erros elevados sem risco pratico.
const stagingNoise: ScenarioFn = (rng) => {
  const assets = makeAssets("staging-noise", 30, { publicFacing: false, hasAuthMiddleware: true });
  const events: SimEvent[] = [];
  pushEvents(events, "staging-noise", assets, 12, () => ({
    signal: buildSignal({
      sast: { hit: true, severity: "medium", confidence: "medium", reachable: true },
      opContext: { lowTrafficStaging: true },
    }),
    groundTruth: false,
  }));
  return {
    id: "staging-noise",
    name: "Ruído de staging",
    description:
      "Achados SAST recorrentes em ambiente de staging de baixo tráfego, sem exposição real de produção.",
    groundTruthNarrative: "negativo",
    assets,
    events,
  };
};

// 6. Scanner instavel (equivalente a port flapping): achado aparece e some
//    entre scans consecutivos sem motivo real.
const flakyScanner: ScenarioFn = (rng) => {
  const assets = makeAssets("flaky-scanner", 20);
  const events: SimEvent[] = [];
  pushEvents(events, "flaky-scanner", assets, 25, () => {
    const flap = randBool(rng, 0.5);
    return {
      signal: buildSignal(
        flap
          ? { sast: { hit: true, severity: "high", confidence: "low", reachable: null } }
          : {},
      ),
      groundTruth: false,
    };
  });
  return {
    id: "flaky-scanner",
    name: "Scanner instável",
    description:
      "Achado SAST intermitente entre execuções consecutivas por instabilidade do próprio scanner — não deve gerar alerta crítico a cada oscilação.",
    groundTruthNarrative: "negativo",
    assets,
    events,
  };
};

// 7. RCE confirmado: multiplas ferramentas concordam, publico, sem auth.
const confirmedRce: ScenarioFn = (rng) => {
  const assets = makeAssets("confirmed-rce", 4, { publicFacing: true, hasAuthMiddleware: false, tier: "critica" });
  const events: SimEvent[] = [];
  pushEvents(events, "confirmed-rce", assets, 15, (_a, _ai, tick) => ({
    signal: buildSignal(
      tick < 2
        ? {}
        : {
            sast: { hit: true, severity: "critical", confidence: "high", reachable: true },
            sca: { hit: true, cvss: 9.8, patchAvailable: false, exploitMaturity: "active" },
            dast: { hit: true, confirmed: true },
          },
    ),
    groundTruth: true,
  }));
  return {
    id: "confirmed-rce",
    name: "RCE confirmado (positivo real)",
    description:
      "SAST, SCA e DAST concordam: vulnerabilidade crítica, pública, sem autenticação, com exploit ativo conhecido.",
    groundTruthNarrative: "positivo",
    assets,
    events,
  };
};

// 8. SQLi confirmado: SAST + DAST concordam, SCA em silencio.
const confirmedSqli: ScenarioFn = (rng) => {
  const assets = makeAssets("confirmed-sqli", 4, { publicFacing: true, hasAuthMiddleware: false, tier: "critica" });
  const events: SimEvent[] = [];
  pushEvents(events, "confirmed-sqli", assets, 15, (_a, _ai, tick) => ({
    signal: buildSignal(
      tick < 2
        ? {}
        : {
            sast: { hit: true, severity: "high", confidence: "high", reachable: true },
            dast: { hit: true, confirmed: true },
          },
    ),
    groundTruth: true,
  }));
  return {
    id: "confirmed-sqli",
    name: "SQL Injection confirmado (positivo real)",
    description: "SAST e DAST concordam sobre uma injeção de SQL explorável em endpoint público.",
    groundTruthNarrative: "positivo",
    assets,
    events,
  };
};

// 9. Modulo depreciado de baixo risco: achados persistentes, sem exposicao.
const deprecatedModule: ScenarioFn = (rng) => {
  const assets = makeAssets("deprecated-module", 20, { publicFacing: false, hasAuthMiddleware: true });
  const events: SimEvent[] = [];
  pushEvents(events, "deprecated-module", assets, 15, () => ({
    signal: buildSignal({
      sast: { hit: true, severity: "high", confidence: "medium", reachable: false },
      codeContext: { deprecatedModule: true },
    }),
    groundTruth: false,
  }));
  return {
    id: "deprecated-module",
    name: "Módulo depreciado",
    description:
      "Achados SAST recorrentes em módulo depreciado, não público, com caminho de código provavelmente inatingível.",
    groundTruthNarrative: "negativo",
    assets,
    events,
  };
};

// 10. Falso disparo em fixture de teste.
const testFixtureFalseTrigger: ScenarioFn = (rng) => {
  const assets = makeAssets("test-fixture", 25);
  const events: SimEvent[] = [];
  pushEvents(events, "test-fixture", assets, 10, () => ({
    signal: buildSignal({
      sast: { hit: true, severity: "high", confidence: "high", reachable: true },
      sca: { hit: true, cvss: 8.1, patchAvailable: false, exploitMaturity: "poc" },
      codeContext: { inTestOrFixture: true },
    }),
    groundTruth: false,
  }));
  return {
    id: "test-fixture",
    name: "Achado em fixture de teste",
    description: "SAST/SCA disparam sobre credenciais e payloads de exemplo usados só em testes.",
    groundTruthNarrative: "negativo",
    assets,
    events,
  };
};

// 11. Compromisso de supply-chain silencioso: so o SCA ve, dificil de detectar.
const silentSupplyChain: ScenarioFn = (rng) => {
  const assets = makeAssets("silent-supply-chain", 2, { publicFacing: true, hasAuthMiddleware: true, tier: "critica" });
  const events: SimEvent[] = [];
  pushEvents(events, "silent-supply-chain", assets, 20, (_a, _ai, tick) => ({
    signal: buildSignal(
      tick < 4
        ? {}
        : {
            sca: { hit: true, cvss: 9.1, patchAvailable: false, exploitMaturity: "active" },
          },
    ),
    groundTruth: true,
  }));
  return {
    id: "silent-supply-chain",
    name: "Compromisso de supply-chain silencioso (positivo real)",
    description:
      "Dependência com exploit ativo conhecido, carregada dinamicamente — SAST não vê o padrão estático e DAST não consegue confirmar. Só o SCA enxerga. Testa se o cluster preserva recall mesmo com um único domínio como evidência.",
    groundTruthNarrative: "positivo",
    assets,
    events,
  };
};

// 12. Ambiguidade multi-sinal em rede interna: achados moderados, baixo risco pratico.
const internalOnlyAmbiguity: ScenarioFn = (rng) => {
  const assets = makeAssets("internal-ambiguity", 18, { publicFacing: false, hasAuthMiddleware: true });
  const events: SimEvent[] = [];
  pushEvents(events, "internal-ambiguity", assets, 15, () => ({
    signal: buildSignal({
      sast: { hit: true, severity: "medium", confidence: "medium", reachable: true },
      sca: { hit: true, cvss: 6.2, patchAvailable: null, exploitMaturity: "none" },
      opContext: { internalOnlyNetwork: true },
    }),
    groundTruth: false,
  }));
  return {
    id: "internal-ambiguity",
    name: "Ambiguidade em rede interna",
    description:
      "Achados moderados e correlacionados, mas em serviço apenas acessível via rede interna — risco prático reduzido.",
    groundTruthNarrative: "negativo",
    assets,
    events,
  };
};

export const SCENARIOS: ScenarioFn[] = [
  dependencyBumpNoise,
  wafShieldedEndpoint,
  secretSprawlProgressive,
  pentestWindow,
  stagingNoise,
  flakyScanner,
  confirmedRce,
  confirmedSqli,
  deprecatedModule,
  testFixtureFalseTrigger,
  silentSupplyChain,
  internalOnlyAmbiguity,
];
