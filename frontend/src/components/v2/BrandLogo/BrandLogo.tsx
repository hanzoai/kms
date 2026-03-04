import { twMerge } from "tailwind-merge";

import { type WhiteLabelBrand, getWhiteLabelBrand } from "@app/helpers/platform";

type Props = {
  className?: string;
  brand?: WhiteLabelBrand;
};

// Real geometric Hanzo H mark (from ~/work/hanzo/logo)
const HanzoLogo = ({ className }: { className?: string }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 67 67"
    fill="none"
    className={twMerge("inline-block", className)}
    aria-label="hanzo logo"
  >
    <path d="M22.21 67V44.6369H0V67H22.21Z" fill="currentColor" />
    <path d="M0 44.6369L22.21 46.8285V44.6369H0Z" fill="currentColor" opacity="0.7" />
    <path d="M66.7038 22.3184H22.2534L0.0878906 44.6367H44.4634L66.7038 22.3184Z" fill="currentColor" />
    <path d="M22.21 0H0V22.3184H22.21V0Z" fill="currentColor" />
    <path d="M66.7198 0H44.5098V22.3184H66.7198V0Z" fill="currentColor" />
    <path d="M66.6753 22.3185L44.5098 20.0822V22.3185H66.6753Z" fill="currentColor" opacity="0.7" />
    <path d="M66.7198 67V44.6369H44.5098V67H66.7198Z" fill="currentColor" />
  </svg>
);

// Simple single-path logos for other brands
const simpleBrands: Record<Exclude<WhiteLabelBrand, "hanzo">, { viewBox: string; d: string }> = {
  lux: {
    viewBox: "0 0 32 32",
    d: "M8 4h5v19h11v5H8V4z"
  },
  zoo: {
    viewBox: "0 0 32 32",
    d: "M6 4h20v5.5L11.5 23H26v5H6v-5.5L20.5 9H6V4z"
  },
  pars: {
    viewBox: "0 0 32 32",
    d: "M8 4h10c4.4 0 8 3.6 8 8s-3.6 8-8 8h-5v8H8V4zm5 12h5c1.65 0 3-1.35 3-3s-1.35-3-3-3h-5v6z"
  }
};

export const BrandLogo = ({ className, brand }: Props) => {
  const resolvedBrand = brand ?? getWhiteLabelBrand();

  if (resolvedBrand === "hanzo") {
    return <HanzoLogo className={className} />;
  }

  const { viewBox, d } = simpleBrands[resolvedBrand];

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={viewBox}
      fill="none"
      className={twMerge("inline-block", className)}
      aria-label={`${resolvedBrand} logo`}
    >
      <path d={d} fill="currentColor" />
    </svg>
  );
};
