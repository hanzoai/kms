import { getWhiteLabelConfig } from "@app/helpers/platform";

export const getBrand = () => {
  const wl = getWhiteLabelConfig();
  return {
    name: wl.name,
    logo: wl.logo,
    favicon: "/favicon.ico"
  };
};
