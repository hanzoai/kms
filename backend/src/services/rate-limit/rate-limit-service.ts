// Rate limit service.
// Reads config from the rate_limit DB table when possible; falls back to
// hardcoded permissive defaults when the table is empty or unreachable.

import { TDbClient } from "@app/db";
import { TableName } from "@app/db/schemas";
import { logger } from "@app/lib/logger";

type TRateLimits = {
  readLimit: number;
  writeLimit: number;
  secretsLimit: number;
  readSecretLimit: number;
  credsLimit: number;
};

const DEFAULTS: TRateLimits = {
  readLimit: 60,
  writeLimit: 200,
  secretsLimit: 40,
  readSecretLimit: 2000,
  credsLimit: 300
};

type TRateLimitServiceFactoryDep = {
  db: TDbClient;
};

export type TRateLimitServiceFactory = ReturnType<typeof rateLimitServiceFactory>;

export const rateLimitServiceFactory = ({ db }: TRateLimitServiceFactoryDep) => {
  const getRateLimits = async (_instanceId?: string): Promise<TRateLimits> => {
    try {
      const row = await db(TableName.RateLimit).first();
      if (!row) return DEFAULTS;

      return {
        readLimit: row.readRateLimit ?? DEFAULTS.readLimit,
        writeLimit: row.writeRateLimit ?? DEFAULTS.writeLimit,
        secretsLimit: row.secretsRateLimit ?? DEFAULTS.secretsLimit,
        readSecretLimit: row.readRateLimit ?? DEFAULTS.readSecretLimit,
        credsLimit: row.authRateLimit ?? DEFAULTS.credsLimit
      };
    } catch (err) {
      logger.warn(err, "rate-limit: DB read failed — using defaults");
      return DEFAULTS;
    }
  };

  const updateRateLimit = async (_data: unknown): Promise<void> => {
    // No-op: rate limit config is managed via DB migrations / admin tooling.
  };

  const initializeBackgroundSync = async () => null as null;

  return { getRateLimits, updateRateLimit, initializeBackgroundSync };
};
