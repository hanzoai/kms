import crypto from "node:crypto";

import { TOKEN_PREFIXES, type Token, type TokenCreateOptions, TokenType } from "./token-types";

const TOKEN_BYTES = 24;
const BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function toBase62(buf: Buffer): string {
  let result = "";
  for (const byte of buf) {
    result += BASE62_CHARS[byte % 62];
  }
  return result;
}

function generateTokenId(type: TokenType): string {
  const random = crypto.randomBytes(TOKEN_BYTES);
  return `${TOKEN_PREFIXES[type]}${toBase62(random)}`;
}

function generateAccessorId(): string {
  return toBase62(crypto.randomBytes(16));
}

/**
 * Salt a token ID for storage lookup (never store raw token IDs)
 */
function saltTokenId(tokenId: string, salt: Buffer): string {
  return crypto.createHmac("sha256", salt).update(tokenId).digest("hex");
}

/**
 * Sign a token payload with HMAC-SHA256 for integrity verification
 */
function signToken(tokenId: string, signingKey: Buffer): string {
  return crypto.createHmac("sha256", signingKey).update(tokenId).digest("base64url");
}

export class TokenStore {
  private tokens = new Map<string, Token>();        // saltedId → Token
  private accessors = new Map<string, string>();     // accessorId → saltedId
  private children = new Map<string, Set<string>>(); // parentSaltedId → Set<childSaltedId>
  private salt: Buffer;
  private signingKey: Buffer;

  constructor(signingKey: Buffer) {
    this.salt = crypto.randomBytes(32);
    this.signingKey = signingKey;
  }

  createToken(options: TokenCreateOptions = {}): { token: Token; clientToken: string } {
    const type = options.type ?? TokenType.Service;
    const tokenId = generateTokenId(type);
    const accessorId = generateAccessorId();
    const saltedId = saltTokenId(tokenId, this.salt);
    const now = new Date();

    const ttl = options.ttl ?? 0;
    const maxTtl = options.maxTtl ?? 0;

    const token: Token = {
      id: saltedId,
      accessorId,
      type,
      displayName: options.displayName ?? "",
      policies: options.policies ?? ["default"],
      entityId: options.entityId,
      parentId: options.parentId ? saltTokenId(options.parentId, this.salt) : undefined,
      ttl,
      maxTtl,
      period: options.period ?? 0,
      numUses: options.numUses ?? 0,
      numUsesRemaining: options.numUses ?? 0,
      creationTime: now,
      expireTime: ttl > 0 ? new Date(now.getTime() + ttl * 1000) : undefined,
      renewable: options.renewable ?? true,
      orphan: options.orphan ?? false,
      metadata: options.metadata ?? {}
    };

    // Batch tokens are stateless - don't store, encode in token itself
    if (type === TokenType.Batch) {
      const payload = Buffer.from(JSON.stringify({
        p: token.policies,
        e: token.entityId,
        x: token.expireTime?.getTime(),
        m: token.metadata
      }));
      const sig = signToken(tokenId + payload.toString("base64url"), this.signingKey);
      const clientToken = `${tokenId}.${payload.toString("base64url")}.${sig}`;
      return { token, clientToken };
    }

    this.tokens.set(saltedId, token);
    this.accessors.set(accessorId, saltedId);

    // Track parent-child relationship
    if (token.parentId && !token.orphan) {
      let childSet = this.children.get(token.parentId);
      if (!childSet) {
        childSet = new Set();
        this.children.set(token.parentId, childSet);
      }
      childSet.add(saltedId);
    }

    return { token, clientToken: tokenId };
  }

  lookupToken(clientToken: string): Token | null {
    // Handle batch tokens (stateless verification)
    if (clientToken.startsWith(TOKEN_PREFIXES[TokenType.Batch])) {
      return this.verifyBatchToken(clientToken);
    }

    const saltedId = saltTokenId(clientToken, this.salt);
    const token = this.tokens.get(saltedId);
    if (!token) return null;

    // Check expiration
    if (token.expireTime && token.expireTime.getTime() <= Date.now()) {
      this.revokeTokenInternal(saltedId);
      return null;
    }

    // Decrement uses
    if (token.numUses > 0) {
      token.numUsesRemaining--;
      if (token.numUsesRemaining <= 0) {
        this.revokeTokenInternal(saltedId);
        return null;
      }
    }

    return { ...token };
  }

  lookupByAccessor(accessorId: string): Omit<Token, "id"> | null {
    const saltedId = this.accessors.get(accessorId);
    if (!saltedId) return null;

    const token = this.tokens.get(saltedId);
    if (!token) return null;

    // Return metadata without the salted ID (security: accessor doesn't reveal token)
    const { id: _, ...rest } = token;
    return rest;
  }

  renewToken(clientToken: string, increment: number): Token {
    const saltedId = saltTokenId(clientToken, this.salt);
    const token = this.tokens.get(saltedId);
    if (!token) throw new Error("token: not found");
    if (!token.renewable) throw new Error("token: not renewable");
    if (token.type === TokenType.Batch) throw new Error("token: batch tokens cannot be renewed");

    const now = new Date();

    // Periodic tokens: renew for period duration
    if (token.period > 0) {
      token.expireTime = new Date(now.getTime() + token.period * 1000);
      token.ttl = token.period;
      return { ...token };
    }

    let newTtl = increment;

    // Cap at maxTTL from creation
    if (token.maxTtl > 0) {
      const maxExpire = token.creationTime.getTime() + token.maxTtl * 1000;
      const requestedExpire = now.getTime() + newTtl * 1000;
      if (requestedExpire > maxExpire) {
        newTtl = Math.max(0, Math.floor((maxExpire - now.getTime()) / 1000));
      }
    }

    token.expireTime = new Date(now.getTime() + newTtl * 1000);
    token.ttl = newTtl;
    return { ...token };
  }

  revokeToken(clientToken: string): void {
    const saltedId = saltTokenId(clientToken, this.salt);
    this.revokeTokenInternal(saltedId);
  }

  revokeTokenTree(clientToken: string): void {
    const saltedId = saltTokenId(clientToken, this.salt);
    this.revokeTreeInternal(saltedId);
  }

  listTokensByEntity(entityId: string): Token[] {
    const result: Token[] = [];
    for (const token of this.tokens.values()) {
      if (token.entityId === entityId) result.push({ ...token });
    }
    return result;
  }

  tidyTokens(): number {
    const now = Date.now();
    let cleaned = 0;
    for (const [id, token] of this.tokens) {
      if (token.expireTime && token.expireTime.getTime() <= now) {
        this.revokeTokenInternal(id);
        cleaned++;
      }
    }
    return cleaned;
  }

  get stats(): { total: number; service: number; batch: number } {
    let service = 0;
    for (const token of this.tokens.values()) {
      if (token.type === TokenType.Service) service++;
    }
    return { total: this.tokens.size, service, batch: 0 };
  }

  // --- Internals ---

  private revokeTokenInternal(saltedId: string): void {
    const token = this.tokens.get(saltedId);
    if (!token) return;

    // Revoke all children first (unless orphan)
    const childIds = this.children.get(saltedId);
    if (childIds) {
      for (const childId of childIds) {
        this.revokeTreeInternal(childId);
      }
      this.children.delete(saltedId);
    }

    // Remove from parent's children set
    if (token.parentId) {
      const parentChildren = this.children.get(token.parentId);
      if (parentChildren) parentChildren.delete(saltedId);
    }

    this.accessors.delete(token.accessorId);
    this.tokens.delete(saltedId);
  }

  private revokeTreeInternal(saltedId: string): void {
    const childIds = this.children.get(saltedId);
    if (childIds) {
      for (const childId of childIds) {
        this.revokeTreeInternal(childId);
      }
    }
    this.revokeTokenInternal(saltedId);
  }

  private verifyBatchToken(clientToken: string): Token | null {
    const parts = clientToken.split(".");
    // hkms_b + random . payload . sig → 3 parts after splitting prefix
    // But prefix contains ".", so we need careful parsing
    const sigIdx = clientToken.lastIndexOf(".");
    const payloadIdx = clientToken.lastIndexOf(".", sigIdx - 1);
    if (payloadIdx < 0 || sigIdx < 0) return null;

    const tokenPart = clientToken.substring(0, payloadIdx);
    const payloadB64 = clientToken.substring(payloadIdx + 1, sigIdx);
    const sig = clientToken.substring(sigIdx + 1);

    // Verify HMAC
    const expected = signToken(tokenPart + payloadB64, this.signingKey);
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      return null;
    }

    try {
      const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

      // Check expiration
      if (payload.x && payload.x <= Date.now()) return null;

      return {
        id: "",
        accessorId: "",
        type: TokenType.Batch,
        displayName: "",
        policies: payload.p ?? ["default"],
        entityId: payload.e,
        ttl: 0,
        maxTtl: 0,
        period: 0,
        numUses: 0,
        numUsesRemaining: 0,
        creationTime: new Date(),
        expireTime: payload.x ? new Date(payload.x) : undefined,
        renewable: false,
        orphan: true,
        metadata: payload.m ?? {}
      };
    } catch {
      return null;
    }
  }
}
