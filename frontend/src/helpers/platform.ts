export const isHanzoCloud = () =>
  window.location.origin.includes("https://kms.hanzo.ai") ||
  window.location.origin.includes("https://us.kms.hanzo.ai") ||
  window.location.origin.includes("https://eu.kms.hanzo.ai") ||
  window.location.origin.includes("https://gamma.kms.hanzo.ai");

export type WhiteLabelBrand = "hanzo" | "lux" | "pars" | "zoo";

export const getWhiteLabelBrand = (): WhiteLabelBrand => {
  const host = window.location.hostname;
  if (host.includes("lux.network")) return "lux";
  if (host.includes("pars.network")) return "pars";
  if (host.includes("zoo.network")) return "zoo";
  return "hanzo";
};

export const getWhiteLabelConfig = () => {
  const brand = getWhiteLabelBrand();
  const configs: Record<WhiteLabelBrand, { name: string; primaryColor: string; logo: string; favicon: string }> = {
    hanzo: { name: "Hanzo KMS", primaryColor: "#ffffff", logo: "/images/hanzo-logo.svg", favicon: "/images/hanzo-favicon.svg" },
    lux:   { name: "Lux KMS",   primaryColor: "#ffffff", logo: "/images/lux-logo.svg",   favicon: "/images/lux-favicon.svg" },
    pars:  { name: "Pars KMS",  primaryColor: "#ffffff", logo: "/images/pars-logo.svg",  favicon: "/images/pars-favicon.svg" },
    zoo:   { name: "Zoo KMS",   primaryColor: "#ffffff", logo: "/images/zoo-logo.svg",   favicon: "/images/zoo-favicon.svg" }
  };
  return configs[brand];
};

export const initBranding = () => {
  const config = getWhiteLabelConfig();
  document.title = config.name;
  const link = document.querySelector<HTMLLinkElement>("link[rel='icon']");
  if (link) {
    link.href = config.favicon;
  }
};
