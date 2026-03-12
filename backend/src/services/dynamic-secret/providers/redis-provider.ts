import crypto from "node:crypto";

import {
  type CredentialOutput,
  type DynamicRole,
  type DynamicSecretProvider,
  generatePassword
} from "./provider-types";

/**
 * Redis ACL dynamic credential provider.
 * Creates temporary Redis users with ACL rules.
 *
 * Requires Redis 6+ with ACL support.
 */
export class RedisProvider implements DynamicSecretProvider {
  readonly type = "redis";
  private connectionUri: string;
  private client: any;

  constructor(connectionUri: string) {
    this.connectionUri = connectionUri;
  }

  async createCredentials(role: DynamicRole): Promise<CredentialOutput> {
    const username = `v-${role.name}-${crypto.randomBytes(4).toString("hex")}`;
    const password = generatePassword(role.passwordPolicy);

    const client = await this.getClient();

    // Default ACL: read-only access
    const aclRules = role.creationStatements.length > 0
      ? role.creationStatements.join(" ")
      : "~* +@read -@dangerous";

    await client.sendCommand(["ACL", "SETUSER", username, "on", `>${password}`, ...aclRules.split(" ")]);

    return { username, password, connectionUri: this.connectionUri };
  }

  async revokeCredentials(username: string): Promise<void> {
    const client = await this.getClient();
    await client.sendCommand(["ACL", "DELUSER", username]);
  }

  async rotatePassword(username: string): Promise<string> {
    const newPassword = generatePassword();
    const client = await this.getClient();
    await client.sendCommand(["ACL", "SETUSER", username, `>${newPassword}`]);
    return newPassword;
  }

  async validateConnection(): Promise<boolean> {
    try {
      const client = await this.getClient();
      const result = await client.sendCommand(["PING"]);
      return result === "PONG";
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    if (this.client) await this.client.quit();
  }

  private async getClient(): Promise<any> {
    if (this.client) return this.client;
    const { createClient } = await import("redis");
    this.client = createClient({ url: this.connectionUri });
    await this.client.connect();
    return this.client;
  }
}
