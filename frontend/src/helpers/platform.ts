const CLOUD_DOMAINS = [
  "kms.hanzo.ai",
  "us.kms.hanzo.ai",
  "eu.kms.hanzo.ai",
  "gamma.kms.hanzo.ai",
  "kms.lux.network",
  "kms.liquidity.io"
];

export const isCloudDeployment = (): boolean => {
  const origin = window.location.origin;
  return CLOUD_DOMAINS.some((d) => origin.includes(d));
};

/** @deprecated Use isCloudDeployment instead */
export const isHanzoCloud = isCloudDeployment;
