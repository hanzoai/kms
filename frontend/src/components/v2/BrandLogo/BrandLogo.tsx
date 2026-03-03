import { twMerge } from "tailwind-merge";

import { type WhiteLabelBrand, getWhiteLabelBrand } from "@app/helpers/platform";

type Props = {
  className?: string;
  brand?: WhiteLabelBrand;
};

const brandPaths: Record<WhiteLabelBrand, { viewBox: string; d: string }> = {
  hanzo: {
    viewBox: "0 0 32 32",
    d: "M6 4h4v10h12V4h4v24h-4V18H10v10H6V4z"
  },
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
  const { viewBox, d } = brandPaths[resolvedBrand];

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
