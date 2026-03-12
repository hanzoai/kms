export interface LeaseEntry {
  id: string;
  path: string;
  issueTime: Date;
  expireTime: Date;
  lastRenewalTime?: Date;
  ttl: number;          // seconds
  maxTtl: number;       // seconds, 0 = no max
  renewable: boolean;
  revokeRetries: number;
  revokedAt?: Date;
  irrevocable: boolean;
  metadata?: Record<string, string>;
}

export interface LeaseOptions {
  ttl: number;
  maxTtl?: number;
  renewable?: boolean;
}

export type RevokeCallback = (leaseId: string) => Promise<void>;

export interface LeaseEvent {
  type: "issued" | "renewed" | "expired" | "revoked" | "revoke_failed";
  leaseId: string;
  path: string;
  timestamp: Date;
  error?: string;
}

export type LeaseEventHandler = (event: LeaseEvent) => void;
