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
  const configs: Record<WhiteLabelBrand, { name: string; primaryColor: string; logo: string }> = {
    hanzo: { name: "Hanzo KMS", primaryColor: "#fd4444", logo: "/images/gradientLogo.svg" },
    lux:   { name: "Lux KMS",   primaryColor: "#6366f1", logo: "/images/gradientLogo.svg" },
    pars:  { name: "Pars KMS",  primaryColor: "#fd4444", logo: "/images/gradientLogo.svg" },
    zoo:   { name: "Zoo KMS",   primaryColor: "#10b981", logo: "/images/gradientLogo.svg" }
  };
  return configs[brand];
};
