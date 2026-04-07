import { twMerge } from "tailwind-merge";

import { type Brand, getBrand } from "@app/helpers/platform";

type Props = {
  className?: string;
  brand?: Brand;
};

// Real geometric Hanzo H mark (from ~/work/hanzo/logo)
const DefaultLogo = ({ className }: { className?: string }) => (
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
type SimpleBrand = { viewBox: string; d: string };
type MultiBrand = { viewBox: string; paths: JSX.Element };
const simpleBrands: Record<Exclude<Brand, "hanzo">, SimpleBrand | MultiBrand> = {
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
  },
  liquidity: {
    viewBox: "0 0 1024 1024",
    paths: (
      <>
        <path d="M 220 220 L 220 720 L 680 720 L 680 620 L 330 620 L 330 220 Z" fill="currentColor" />
        <path d="M 400 500 Q 500 420 600 500 Q 700 580 800 500" stroke="currentColor" strokeWidth="12" fill="none" strokeLinecap="round" opacity="0.5" />
        <path d="M 400 560 Q 500 480 600 560 Q 700 640 800 560" stroke="currentColor" strokeWidth="8" fill="none" strokeLinecap="round" opacity="0.3" />
      </>
    )
  }
};

export const BrandLogo = ({ className, brand }: Props) => {
  const resolvedBrand = brand ?? getBrand();

  if (resolvedBrand === "hanzo") {
    return <DefaultLogo className={className} />;
  }

  const entry = simpleBrands[resolvedBrand];

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={entry.viewBox}
      fill="none"
      className={twMerge("inline-block", className)}
      aria-label={`${resolvedBrand} logo`}
    >
      {"d" in entry ? <path d={entry.d} fill="currentColor" /> : entry.paths}
    </svg>
  );
};
