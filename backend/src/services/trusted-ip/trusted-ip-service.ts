// MIT License
// Community edition: trusted IP enforcement is disabled; all IPs are allowed.

export type TTrustedIpServiceFactory = ReturnType<typeof trustedIpServiceFactory>;

export const trustedIpServiceFactory = () => {
  const getTrustedIps = async (_projectId: string) => [] as unknown[];

  const addTrustedIp = async (_data: unknown) => ({}) as unknown;

  const updateTrustedIp = async (_data: unknown) => ({}) as unknown;

  const deleteTrustedIp = async (_data: unknown) => ({}) as unknown;

  const isIpAllowed = (_projectId: string, _ip: string) => true;

  return { getTrustedIps, addTrustedIp, updateTrustedIp, deleteTrustedIp, isIpAllowed };
};
