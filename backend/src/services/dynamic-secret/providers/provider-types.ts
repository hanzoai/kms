export interface CredentialOutput {
  username: string;
  password: string;
  connectionUri?: string;
  metadata?: Record<string, string>;
}

export interface DynamicSecretProvider {
  type: string;
  createCredentials(role: DynamicRole): Promise<CredentialOutput>;
  revokeCredentials(username: string): Promise<void>;
  rotatePassword(username: string): Promise<string>;
  validateConnection(): Promise<boolean>;
  close(): Promise<void>;
}

export interface DatabaseConfig {
  type: "postgresql" | "mysql" | "mongodb" | "redis";
  connectionUri: string;
  maxOpenConnections?: number;
  maxIdleConnections?: number;
  maxConnectionLifetimeSeconds?: number;
  rootRotationStatements?: string[];
}

export interface DynamicRole {
  name: string;
  dbConfig: string;          // reference to DatabaseConfig name
  defaultTtl: number;        // seconds
  maxTtl: number;            // seconds
  creationStatements: string[];
  revocationStatements: string[];
  rotationStatements?: string[];
  credentialType?: "password" | "rsa_private_key";
  passwordPolicy?: PasswordPolicy;
}

export interface StaticRole {
  name: string;
  dbConfig: string;
  username: string;
  rotationPeriod: number;    // seconds
  rotationStatements?: string[];
}

export interface PasswordPolicy {
  length: number;
  charset: string;
}

const DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
const DEFAULT_LENGTH = 24;

export function generatePassword(policy?: PasswordPolicy): string {
  const { length, charset } = {
    length: policy?.length ?? DEFAULT_LENGTH,
    charset: policy?.charset ?? DEFAULT_CHARSET
  };

  const bytes = require("node:crypto").randomBytes(length);
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset[bytes[i] % charset.length];
  }
  return password;
}

/**
 * Resolve template variables in SQL statements.
 * {{name}} → username, {{password}} → password, {{expiration}} → ISO timestamp
 */
export function resolveStatementTemplate(
  statement: string,
  vars: { name: string; password: string; expiration?: string }
): string {
  return statement
    .replace(/\{\{name\}\}/g, vars.name)
    .replace(/\{\{password\}\}/g, vars.password)
    .replace(/\{\{expiration\}\}/g, vars.expiration ?? "");
}
