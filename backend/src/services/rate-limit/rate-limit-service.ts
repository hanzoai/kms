// MIT License
// Community edition: returns static permissive rate limits.

export type TRateLimitServiceFactory = ReturnType<typeof rateLimitServiceFactory>;

export const rateLimitServiceFactory = () => {
  const getRateLimits = async (_instanceId?: string) => ({
    readLimit: 60,
    writeLimit: 200,
    secretsLimit: 40,
    readSecretLimit: 2000,
    credsLimit: 300
  });

  const updateRateLimit = async (_data: unknown) => {};

  const initializeBackgroundSync = async () => null as null;

  return { getRateLimits, updateRateLimit, initializeBackgroundSync };
};
