import { describe, it, expect } from "vitest";
import {
  certaintyDegree,
  contradictionDegree,
  combineEvidence,
  classify,
  classifyCluster,
  DEFAULT_THRESHOLDS,
} from "../src/core/paraconsistent.js";

describe("certaintyDegree / contradictionDegree", () => {
  it("GC = mu - lambda", () => {
    expect(certaintyDegree({ mu: 0.8, lambda: 0.2 })).toBeCloseTo(0.6);
  });

  it("GCT = mu + lambda - 1", () => {
    expect(contradictionDegree({ mu: 0.8, lambda: 0.8 })).toBeCloseTo(0.6);
    expect(contradictionDegree({ mu: 0.1, lambda: 0.1 })).toBeCloseTo(-0.8);
  });
});

describe("combineEvidence", () => {
  it("faz media ponderada de mu e lambda separadamente", () => {
    const combined = combineEvidence([
      { evidence: { mu: 1, lambda: 0 }, weight: 1 },
      { evidence: { mu: 0, lambda: 1 }, weight: 1 },
    ]);
    expect(combined.mu).toBeCloseTo(0.5);
    expect(combined.lambda).toBeCloseTo(0.5);
  });

  it("evidencia de maior peso domina o resultado", () => {
    const combined = combineEvidence([
      { evidence: { mu: 1, lambda: 0 }, weight: 9 },
      { evidence: { mu: 0, lambda: 1 }, weight: 1 },
    ]);
    expect(combined.mu).toBeGreaterThan(0.8);
  });
});

describe("classify", () => {
  it("evidencia forte e sem contradicao => critico", () => {
    expect(classify({ mu: 0.95, lambda: 0.05 })).toBe("critico");
  });

  it("sem evidencia em nenhum sentido => normal", () => {
    expect(classify({ mu: 0.05, lambda: 0.05 })).toBe("normal");
  });

  it("mu e lambda altos simultaneamente => inconsistente, nunca critico", () => {
    const e = { mu: 0.85, lambda: 0.75 };
    expect(contradictionDegree(e)).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.contradiction);
    expect(classify(e)).toBe("inconsistente");
  });
});

describe("classifyCluster", () => {
  it("usa o sinal de contradicao (extremos) mesmo quando a media dilui o conflito", () => {
    // Media: mu=0.5, lambda=0.5 -> GCT=0, nao pareceria contraditorio.
    const aggregated = { mu: 0.5, lambda: 0.5 };
    // Mas o extremo entre dominios mostra conflito real (um domino grita
    // "sim", outro grita "nao") -> deve ser inconsistente, nao normal/critico.
    const contradiction = { mu: 0.9, lambda: 0.8 };
    expect(classifyCluster(aggregated, contradiction)).toBe("inconsistente");
  });

  it("sem conflito nos extremos, usa o GC da media agregada para o ranking", () => {
    const aggregated = { mu: 0.9, lambda: 0.05 };
    const contradiction = { mu: 0.9, lambda: 0.1 };
    expect(classifyCluster(aggregated, contradiction)).toBe("critico");
  });
});
