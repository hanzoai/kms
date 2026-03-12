import crypto from "node:crypto";

import {
  type CredentialOutput,
  type DynamicRole,
  type DynamicSecretProvider,
  generatePassword,
  resolveStatementTemplate
} from "./provider-types";

/**
 * SQL dynamic credential provider for PostgreSQL and MySQL.
 * Generates temporary database users with role-based permissions.
 *
 * Creation statements example:
 *   CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
 *   GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";
 *
 * Revocation statements example:
 *   REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "{{name}}";
 *   DROP ROLE IF EXISTS "{{name}}";
 */
export class SqlProvider implements DynamicSecretProvider {
  readonly type = "sql";
  private connectionUri: string;
  private pool: any; // pg.Pool or mysql2.Pool - lazy loaded

  constructor(connectionUri: string) {
    this.connectionUri = connectionUri;
  }

  async createCredentials(role: DynamicRole): Promise<CredentialOutput> {
    const username = `v-${role.name}-${crypto.randomBytes(4).toString("hex")}`;
    const password = generatePassword(role.passwordPolicy);
    const expiration = new Date(Date.now() + role.defaultTtl * 1000).toISOString();

    const pool = await this.getPool();

    for (const stmt of role.creationStatements) {
      const resolved = resolveStatementTemplate(stmt, { name: username, password, expiration });
      await pool.query(resolved);
    }

    return { username, password, connectionUri: this.connectionUri };
  }

  async revokeCredentials(username: string): Promise<void> {
    const pool = await this.getPool();
    // Default revocation: terminate connections then drop role
    await pool.query(`
      SELECT pg_terminate_backend(pid)
      FROM pg_stat_activity
      WHERE usename = $1
    `, [username]).catch(() => {});

    await pool.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "${username}"`).catch(() => {});
    await pool.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM "${username}"`).catch(() => {});
    await pool.query(`DROP ROLE IF EXISTS "${username}"`);
  }

  async rotatePassword(username: string): Promise<string> {
    const newPassword = generatePassword();
    const pool = await this.getPool();
    await pool.query(`ALTER ROLE "${username}" WITH PASSWORD '${newPassword}'`);
    return newPassword;
  }

  async validateConnection(): Promise<boolean> {
    try {
      const pool = await this.getPool();
      await pool.query("SELECT 1");
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    if (this.pool) await this.pool.end();
  }

  private async getPool(): Promise<any> {
    if (this.pool) return this.pool;
    // Dynamic import to avoid hard dependency
    const { Pool } = await import("pg");
    this.pool = new Pool({ connectionString: this.connectionUri, max: 5 });
    return this.pool;
  }
}
