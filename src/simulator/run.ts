import type { Asset, SimEvent } from "../core/types.js";
import { makeRng } from "../core/rng.js";
import { SCENARIOS, type ScenarioResult } from "./scenarios.js";

export interface SimulationData {
  scenarios: ScenarioResult[];
  assets: Map<string, Asset>;
  /** Eventos ordenados por cenario e tick (a ordem importa para a persistencia temporal). */
  events: SimEvent[];
}

export function buildSimulation(seed: number): SimulationData {
  const rng = makeRng(seed);
  const scenarios = SCENARIOS.map((scenario) => scenario(rng));

  const assets = new Map<string, Asset>();
  const events: SimEvent[] = [];
  for (const scenario of scenarios) {
    for (const asset of scenario.assets) assets.set(asset.id, asset);
    for (const event of scenario.events) events.push(event);
  }

  return { scenarios, assets, events };
}
