import { getBrandConfig } from "@app/helpers/platform";

export const getBrand = () => {
  const wl = getBrandConfig();
  return {
    name: wl.name,
    logo: wl.logo,
    favicon: wl.favicon
  };
};
