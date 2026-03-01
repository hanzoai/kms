// MIT License
// Type definitions for the rate limit service.

export type TRateLimitServiceFactory = {
  getRateLimits: (instanceId?: string) => Promise<{
    readLimit: number;
    writeLimit: number;
    secretsLimit: number;
    readSecretLimit: number;
    credsLimit: number;
  }>;
  updateRateLimit: (data: unknown) => Promise<void>;
};
