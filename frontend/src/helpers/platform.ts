// Brand detection from hostname. One way — no "white label" concept.
// Each deployment IS the brand based on its domain.

export type Brand = "hanzo" | "lux" | "pars" | "zoo" | "liquidity";

export const getBrand = (): Brand => {
  const host = window.location.hostname;
  if (host.includes("satschel.com") || host.includes("liquidity.io")) return "liquidity";
  if (host.includes("lux.network") || host.includes("lux.exchange")) return "lux";
  if (host.includes("pars.network") || host.includes("pars.market")) return "pars";
  if (host.includes("zoo.network") || host.includes("zoo.ngo") || host.includes("zoo.exchange")) return "zoo";
  return "hanzo";
};

export const isCloud = () => {
  const host = window.location.hostname;
  return host.includes("hanzo.ai") || host.includes("lux.network") ||
    host.includes("pars.network") || host.includes("zoo.ngo") ||
    host.includes("satschel.com") || host.includes("liquidity.io");
};

const brandConfig: Record<Brand, { name: string; primaryColor: string }> = {
  hanzo:     { name: "Hanzo KMS",     primaryColor: "#ffffff" },
  lux:       { name: "Lux KMS",       primaryColor: "#ffffff" },
  pars:      { name: "Pars KMS",      primaryColor: "#ffffff" },
  zoo:       { name: "Zoo KMS",       primaryColor: "#ffffff" },
  liquidity: { name: "Liquidity KMS", primaryColor: "#ffffff" },
};

export const getBrandConfig = () => brandConfig[getBrand()];

export const initBranding = () => {
  const config = getBrandConfig();
  document.title = config.name;
};

// Backward compat — remove these imports from callers over time
export const getWhiteLabelBrand = getBrand;
export const getWhiteLabelConfig = getBrandConfig;
export type WhiteLabelBrand = Brand;
export const isHanzoCloud = isCloud;
