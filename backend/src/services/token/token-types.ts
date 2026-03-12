export enum TokenType {
  Service = "service",
  Batch = "batch",
  Recovery = "recovery"
}

export interface Token {
  id: string;          // hkms_s.{random} or hkms_b.{random}
  accessorId: string;  // separate random ID for indirect lookup
  type: TokenType;
  displayName: string;
  policies: string[];
  entityId?: string;
  parentId?: string;
  ttl: number;         // seconds
  maxTtl: number;      // seconds, 0 = no max
  period: number;      // seconds, 0 = not periodic
  numUses: number;     // 0 = unlimited
  numUsesRemaining: number;
  creationTime: Date;
  expireTime?: Date;   // undefined for non-expiring (root)
  renewable: boolean;
  orphan: boolean;
  metadata: Record<string, string>;
}

export interface TokenCreateOptions {
  type?: TokenType;
  displayName?: string;
  policies?: string[];
  entityId?: string;
  parentId?: string;
  ttl?: number;
  maxTtl?: number;
  period?: number;
  numUses?: number;
  renewable?: boolean;
  orphan?: boolean;
  metadata?: Record<string, string>;
}

export const TOKEN_PREFIXES: Record<TokenType, string> = {
  [TokenType.Service]: "hkms_s.",
  [TokenType.Batch]: "hkms_b.",
  [TokenType.Recovery]: "hkms_r."
};
