import type { DatabaseConfig, DynamicSecretProvider } from "./provider-types";
import { MongoDBProvider } from "./mongodb-provider";
import { RedisProvider } from "./redis-provider";
import { SqlProvider } from "./sql-provider";

export function createProvider(config: DatabaseConfig): DynamicSecretProvider {
  switch (config.type) {
    case "postgresql":
    case "mysql":
      return new SqlProvider(config.connectionUri);
    case "redis":
      return new RedisProvider(config.connectionUri);
    case "mongodb":
      return new MongoDBProvider(config.connectionUri);
    default:
      throw new Error(`dynamic-secret: unsupported database type: ${config.type}`);
  }
}
