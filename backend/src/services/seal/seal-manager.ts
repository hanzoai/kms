import crypto from "node:crypto";

import { combine, split } from "@app/lib/crypto/shamir";

import { Barrier } from "./barrier";
import { type KmsWrapper, type SealConfig, SealType, type SealStatus } from "./seal-types";

/**
 * Seal Manager orchestrates barrier initialization and unseal flow.
 *
 * Shamir mode: root key split into N shares, T required to reconstruct.
 * Auto-unseal mode: root key encrypted by external KMS, auto-decrypted on startup.
 */
export class SealManager {
  private barrier: Barrier;
  private config: SealConfig;
  private initialized = false;
  private unsealShares: Buffer[] = [];
  private recoveryShares: Buffer[] = [];
  private recoveryConfig?: SealConfig;
  private kmsWrapper?: KmsWrapper;
  private encryptedRootKey?: Buffer;
  private healthCheckInterval?: ReturnType<typeof setInterval>;

  constructor(config?: Partial<SealConfig>) {
    this.barrier = new Barrier();
    this.config = {
      type: config?.type ?? SealType.Shamir,
      secretShares: config?.secretShares ?? 5,
      secretThreshold: config?.secretThreshold ?? 3
    };
  }

  destroy(): void {
    if (this.healthCheckInterval) clearInterval(this.healthCheckInterval);
  }

  /**
   * Initialize the seal - generates root key, splits into shares (Shamir)
   * or encrypts with KMS (auto-unseal)
   */
  async initialize(): Promise<{ shares?: string[]; recoveryShares?: string[]; rootToken: string }> {
    if (this.initialized) throw new Error("seal: already initialized");

    const rootKey = crypto.randomBytes(32);

    if (this.config.type === SealType.Shamir) {
      // Split root key into Shamir shares
      const shares = split(rootKey, this.config.secretShares, this.config.secretThreshold);
      this.barrier.initialize(rootKey);
      this.initialized = true;

      // Generate a root token
      const rootToken = `hkms_r.${crypto.randomBytes(24).toString("base64url")}`;

      return {
        shares: shares.map((s) => s.toString("base64")),
        rootToken
      };
    }

    // Auto-unseal: encrypt root key with KMS wrapper
    if (!this.kmsWrapper) throw new Error("seal: KMS wrapper required for auto-unseal");

    this.encryptedRootKey = await this.kmsWrapper.encrypt(rootKey);
    this.barrier.initialize(rootKey);
    this.initialized = true;

    // Generate recovery shares (Shamir backup for KMS failure)
    const recoveryShareCount = this.recoveryConfig?.secretShares ?? 5;
    const recoveryThreshold = this.recoveryConfig?.secretThreshold ?? 3;
    const recShares = split(rootKey, recoveryShareCount, recoveryThreshold);

    const rootToken = `hkms_r.${crypto.randomBytes(24).toString("base64url")}`;

    // Start health check
    this.startHealthCheck();

    return {
      recoveryShares: recShares.map((s) => s.toString("base64")),
      rootToken
    };
  }

  /**
   * Provide a Shamir unseal share. Returns status after processing.
   */
  unseal(shareBase64: string): SealStatus {
    if (!this.initialized) throw new Error("seal: not initialized");
    if (!this.barrier.isSealed) return this.status();
    if (this.config.type !== SealType.Shamir) throw new Error("seal: use auto-unseal for KMS-backed seals");

    const share = Buffer.from(shareBase64, "base64");
    this.unsealShares.push(share);

    if (this.unsealShares.length >= this.config.secretThreshold) {
      try {
        const rootKey = combine(this.unsealShares);
        this.barrier.unseal(rootKey);
        this.unsealShares = [];
      } catch {
        this.unsealShares = [];
        throw new Error("seal: failed to reconstruct root key from shares");
      }
    }

    return this.status();
  }

  /**
   * Auto-unseal using configured KMS wrapper
   */
  async autoUnseal(): Promise<SealStatus> {
    if (!this.initialized) throw new Error("seal: not initialized");
    if (!this.barrier.isSealed) return this.status();
    if (!this.kmsWrapper) throw new Error("seal: no KMS wrapper configured");
    if (!this.encryptedRootKey) throw new Error("seal: no encrypted root key stored");

    const rootKey = await this.kmsWrapper.decrypt(this.encryptedRootKey);
    this.barrier.unseal(rootKey);
    this.startHealthCheck();

    return this.status();
  }

  /**
   * Seal the barrier
   */
  seal(): SealStatus {
    this.barrier.seal();
    this.unsealShares = [];
    return this.status();
  }

  /**
   * Rotate the root key (generates new key, re-wraps with KMS if applicable)
   */
  async rotateMasterKey(): Promise<void> {
    if (this.barrier.isSealed) throw new Error("seal: cannot rotate while sealed");

    const newTerm = this.barrier.rotate();

    if (this.config.type !== SealType.Shamir && this.kmsWrapper) {
      // Re-encrypt the keyring with KMS
      const rootKey = crypto.randomBytes(32);
      this.encryptedRootKey = await this.kmsWrapper.encrypt(rootKey);
    }
  }

  status(): SealStatus {
    return {
      sealed: this.barrier.isSealed,
      type: this.config.type,
      totalShares: this.config.secretShares,
      threshold: this.config.secretThreshold,
      unsealProgress: this.unsealShares.length,
      unsealKeysProvided: this.unsealShares.length,
      initialized: this.initialized,
      version: this.barrier.activeTerm
    };
  }

  /**
   * Set KMS wrapper for auto-unseal
   */
  setKmsWrapper(wrapper: KmsWrapper, recoveryConfig?: SealConfig): void {
    this.kmsWrapper = wrapper;
    this.recoveryConfig = recoveryConfig;
    this.config.type = SealType.AwsKms; // or GcpKms depending on wrapper
  }

  /**
   * Set encrypted root key (loaded from storage on restart)
   */
  setEncryptedRootKey(key: Buffer): void {
    this.encryptedRootKey = key;
    this.initialized = true;
  }

  /**
   * Access the barrier for encrypt/decrypt operations
   */
  getBarrier(): Barrier {
    return this.barrier;
  }

  private startHealthCheck(): void {
    if (this.healthCheckInterval) clearInterval(this.healthCheckInterval);
    if (!this.kmsWrapper) return;

    this.healthCheckInterval = setInterval(async () => {
      try {
        const healthy = await this.kmsWrapper!.isHealthy();
        if (!healthy) {
          // Log warning but don't seal - KMS may recover
        }
      } catch {
        // Log error
      }
    }, 600_000); // 10 minutes
  }
}
