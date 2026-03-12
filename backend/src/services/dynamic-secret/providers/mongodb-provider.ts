import crypto from "node:crypto";

import {
  type CredentialOutput,
  type DynamicRole,
  type DynamicSecretProvider,
  generatePassword
} from "./provider-types";

/**
 * MongoDB dynamic credential provider.
 * Creates temporary database users with role-based permissions.
 */
export class MongoDBProvider implements DynamicSecretProvider {
  readonly type = "mongodb";
  private connectionUri: string;
  private client: any;

  constructor(connectionUri: string) {
    this.connectionUri = connectionUri;
  }

  async createCredentials(role: DynamicRole): Promise<CredentialOutput> {
    const username = `v-${role.name}-${crypto.randomBytes(4).toString("hex")}`;
    const password = generatePassword(role.passwordPolicy);

    const client = await this.getClient();
    const db = client.db("admin");

    // Default roles from creation statements or fallback to readWrite
    const roles = role.creationStatements.length > 0
      ? role.creationStatements.map((r) => {
          try { return JSON.parse(r); } catch { return { role: r, db: "admin" }; }
        })
      : [{ role: "readWrite", db: "admin" }];

    await db.command({
      createUser: username,
      pwd: password,
      roles
    });

    return { username, password, connectionUri: this.connectionUri };
  }

  async revokeCredentials(username: string): Promise<void> {
    const client = await this.getClient();
    const db = client.db("admin");
    await db.command({ dropUser: username }).catch(() => {});
  }

  async rotatePassword(username: string): Promise<string> {
    const newPassword = generatePassword();
    const client = await this.getClient();
    const db = client.db("admin");
    await db.command({ updateUser: username, pwd: newPassword });
    return newPassword;
  }

  async validateConnection(): Promise<boolean> {
    try {
      const client = await this.getClient();
      await client.db("admin").command({ ping: 1 });
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    if (this.client) await this.client.close();
  }

  private async getClient(): Promise<any> {
    if (this.client) return this.client;
    const { MongoClient } = await import("mongodb");
    this.client = new MongoClient(this.connectionUri);
    await this.client.connect();
    return this.client;
  }
}
