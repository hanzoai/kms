import crypto from "node:crypto";

import type { LeaseEntry, LeaseEvent, LeaseEventHandler, LeaseOptions, RevokeCallback } from "./lease-types";

const MAX_REVOKE_RETRIES = 6;
const BASE_RETRY_DELAY_MS = 1000;
const DEFAULT_CHECK_INTERVAL_MS = 10_000;
const MAX_CONCURRENT_REVOCATIONS = 200;

export class LeaseManager {
  private leases = new Map<string, LeaseEntry>();
  private revokeCallbacks = new Map<string, RevokeCallback>();
  private pendingTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private eventHandlers: LeaseEventHandler[] = [];
  private checkInterval?: ReturnType<typeof setInterval>;
  private activeRevocations = 0;
  private revocationQueue: string[] = [];

  constructor(checkIntervalMs = DEFAULT_CHECK_INTERVAL_MS) {
    this.checkInterval = setInterval(() => this.sweep(), checkIntervalMs);
  }

  destroy(): void {
    if (this.checkInterval) clearInterval(this.checkInterval);
    for (const timer of this.pendingTimers.values()) clearTimeout(timer);
    this.pendingTimers.clear();
  }

  onEvent(handler: LeaseEventHandler): void {
    this.eventHandlers.push(handler);
  }

  register(
    path: string,
    options: LeaseOptions,
    revokeCallback: RevokeCallback,
    metadata?: Record<string, string>
  ): string {
    const id = crypto.randomUUID();
    const now = new Date();
    const ttl = options.ttl;
    const maxTtl = options.maxTtl ?? 0;

    const entry: LeaseEntry = {
      id,
      path,
      issueTime: now,
      expireTime: new Date(now.getTime() + ttl * 1000),
      ttl,
      maxTtl,
      renewable: options.renewable ?? true,
      revokeRetries: 0,
      irrevocable: false,
      metadata
    };

    this.leases.set(id, entry);
    this.revokeCallbacks.set(id, revokeCallback);
    this.scheduleExpiration(id, ttl * 1000);
    this.emit({ type: "issued", leaseId: id, path, timestamp: now });

    return id;
  }

  renew(leaseId: string, increment: number): LeaseEntry {
    const entry = this.leases.get(leaseId);
    if (!entry) throw new Error(`lease: "${leaseId}" not found`);
    if (!entry.renewable) throw new Error(`lease: "${leaseId}" is not renewable`);
    if (entry.irrevocable) throw new Error(`lease: "${leaseId}" is irrevocable`);

    const now = new Date();
    let newTtl = increment;

    // Cap at maxTTL from issue time
    if (entry.maxTtl > 0) {
      const maxExpire = entry.issueTime.getTime() + entry.maxTtl * 1000;
      const requestedExpire = now.getTime() + newTtl * 1000;
      if (requestedExpire > maxExpire) {
        newTtl = Math.max(0, Math.floor((maxExpire - now.getTime()) / 1000));
      }
    }

    entry.expireTime = new Date(now.getTime() + newTtl * 1000);
    entry.ttl = newTtl;
    entry.lastRenewalTime = now;

    // Reschedule expiration timer
    const existing = this.pendingTimers.get(leaseId);
    if (existing) clearTimeout(existing);
    this.scheduleExpiration(leaseId, newTtl * 1000);

    this.emit({ type: "renewed", leaseId, path: entry.path, timestamp: now });
    return { ...entry };
  }

  async revoke(leaseId: string, force = false): Promise<void> {
    const entry = this.leases.get(leaseId);
    if (!entry) return; // already revoked

    const timer = this.pendingTimers.get(leaseId);
    if (timer) clearTimeout(timer);
    this.pendingTimers.delete(leaseId);

    if (force) {
      this.leases.delete(leaseId);
      this.revokeCallbacks.delete(leaseId);
      this.emit({ type: "revoked", leaseId, path: entry.path, timestamp: new Date() });
      return;
    }

    await this.executeRevocation(leaseId);
  }

  async revokeByPrefix(prefix: string): Promise<void> {
    const toRevoke: string[] = [];
    for (const [id, entry] of this.leases) {
      if (entry.path.startsWith(prefix)) toRevoke.push(id);
    }
    await Promise.all(toRevoke.map((id) => this.revoke(id)));
  }

  getLeaseInfo(leaseId: string): LeaseEntry | undefined {
    const entry = this.leases.get(leaseId);
    return entry ? { ...entry } : undefined;
  }

  listByPrefix(prefix: string): LeaseEntry[] {
    const result: LeaseEntry[] = [];
    for (const entry of this.leases.values()) {
      if (entry.path.startsWith(prefix)) result.push({ ...entry });
    }
    return result.sort((a, b) => a.expireTime.getTime() - b.expireTime.getTime());
  }

  listIrrevocable(): LeaseEntry[] {
    const result: LeaseEntry[] = [];
    for (const entry of this.leases.values()) {
      if (entry.irrevocable) result.push({ ...entry });
    }
    return result;
  }

  get stats(): { total: number; active: number; irrevocable: number } {
    let active = 0;
    let irrevocable = 0;
    for (const entry of this.leases.values()) {
      if (entry.irrevocable) irrevocable++;
      else active++;
    }
    return { total: this.leases.size, active, irrevocable };
  }

  // --- Internals ---

  private scheduleExpiration(leaseId: string, delayMs: number): void {
    const timer = setTimeout(() => {
      this.pendingTimers.delete(leaseId);
      this.enqueueRevocation(leaseId);
    }, delayMs);
    this.pendingTimers.set(leaseId, timer);
  }

  private enqueueRevocation(leaseId: string): void {
    if (this.activeRevocations >= MAX_CONCURRENT_REVOCATIONS) {
      this.revocationQueue.push(leaseId);
      return;
    }
    this.activeRevocations++;
    this.executeRevocation(leaseId).finally(() => {
      this.activeRevocations--;
      this.drainQueue();
    });
  }

  private drainQueue(): void {
    while (this.revocationQueue.length > 0 && this.activeRevocations < MAX_CONCURRENT_REVOCATIONS) {
      const leaseId = this.revocationQueue.shift()!;
      this.activeRevocations++;
      this.executeRevocation(leaseId).finally(() => {
        this.activeRevocations--;
        this.drainQueue();
      });
    }
  }

  private async executeRevocation(leaseId: string): Promise<void> {
    const entry = this.leases.get(leaseId);
    if (!entry) return;

    const callback = this.revokeCallbacks.get(leaseId);
    if (!callback) {
      this.leases.delete(leaseId);
      return;
    }

    try {
      await callback(leaseId);
      entry.revokedAt = new Date();
      this.leases.delete(leaseId);
      this.revokeCallbacks.delete(leaseId);
      this.emit({ type: "revoked", leaseId, path: entry.path, timestamp: new Date() });
    } catch (err: any) {
      entry.revokeRetries++;
      if (entry.revokeRetries >= MAX_REVOKE_RETRIES) {
        entry.irrevocable = true;
        this.revokeCallbacks.delete(leaseId);
        this.emit({
          type: "revoke_failed",
          leaseId,
          path: entry.path,
          timestamp: new Date(),
          error: `max retries exceeded: ${err.message}`
        });
      } else {
        // Exponential backoff retry
        const delay = BASE_RETRY_DELAY_MS * Math.pow(2, entry.revokeRetries - 1);
        this.scheduleExpiration(leaseId, delay);
        this.emit({
          type: "revoke_failed",
          leaseId,
          path: entry.path,
          timestamp: new Date(),
          error: `retry ${entry.revokeRetries}/${MAX_REVOKE_RETRIES}: ${err.message}`
        });
      }
    }
  }

  private sweep(): void {
    const now = Date.now();
    for (const [id, entry] of this.leases) {
      if (entry.irrevocable) continue;
      if (entry.expireTime.getTime() <= now && !this.pendingTimers.has(id)) {
        this.enqueueRevocation(id);
      }
    }
  }

  private emit(event: LeaseEvent): void {
    for (const handler of this.eventHandlers) {
      try {
        handler(event);
      } catch {
        // swallow handler errors
      }
    }
  }
}
