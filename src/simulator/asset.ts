import type { Asset, AssetTier } from "../core/types.js";

export function makeAssets(
  scenarioId: string,
  count: number,
  overrides: Partial<Asset> = {},
): Asset[] {
  const assets: Asset[] = [];
  for (let i = 0; i < count; i++) {
    assets.push({
      id: `${scenarioId}-asset-${i}`,
      name: `${scenarioId}-asset-${i}`,
      tier: "media" as AssetTier,
      publicFacing: false,
      hasAuthMiddleware: true,
      ...overrides,
    });
  }
  return assets;
}
