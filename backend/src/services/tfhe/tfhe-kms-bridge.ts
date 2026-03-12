import crypto from "node:crypto";

import {
  type DecryptionShare,
  type DecryptionShareRequest,
  type EncryptedPolicyState,
  type EncryptedValue,
  FheKeyType,
  type PrivatePolicyRule,
  type TChainFheConfig,
  type TfheComputeRequest,
  type TfheKeyConfig,
  TfheOperation
} from "./tfhe-types";

/**
 * TFHE-KMS Bridge
 *
 * Manages FHE key lifecycle in KMS and coordinates with MPC cluster
 * for threshold keygen, encryption, and decryption.
 *
 * Flow:
 *   1. KMS creates TFHE key config → stores metadata + policy
 *   2. Bridge sends keygen request to MPC cluster via NATS
 *   3. MPC nodes run TFHE DKG (luxfi/fhe threshold keygen)
 *   4. Each node stores its key share locally (BadgerDB)
 *   5. KMS stores public key reference + metadata
 *   6. Encrypt: client sends plaintext → KMS encrypts with public key
 *   7. Compute: homomorphic operations on encrypted data (server-side)
 *   8. Decrypt: threshold decryption via MPC (t-of-n shares required)
 */
export class TfheKmsBridge {
  private keys = new Map<string, TfheKeyConfig>();
  private publicKeys = new Map<string, Buffer>();
  private mpcEndpoint?: string;
  private tChainConfig?: TChainFheConfig;

  constructor(options?: { mpcEndpoint?: string; tChainConfig?: TChainFheConfig }) {
    this.mpcEndpoint = options?.mpcEndpoint;
    this.tChainConfig = options?.tChainConfig;
  }

  /**
   * Register a new TFHE key in KMS and trigger threshold keygen via MPC
   */
  async createKey(
    name: string,
    options: {
      keyType?: FheKeyType;
      threshold?: number;
      totalParties?: number;
    } = {}
  ): Promise<TfheKeyConfig> {
    const id = crypto.randomUUID();
    const walletId = `tfhe-${crypto.randomBytes(8).toString("hex")}`;

    const config: TfheKeyConfig = {
      id,
      name,
      walletId,
      keyType: options.keyType ?? FheKeyType.TFHE_UINT64,
      threshold: options.threshold ?? 2,
      totalParties: options.totalParties ?? 3,
      generation: 1,
      publicKeyRef: `tfhe:${id}:pubkey`,
      status: "pending",
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.keys.set(id, config);

    // Trigger MPC keygen (async - status transitions to "active" on completion)
    if (this.mpcEndpoint) {
      await this.triggerMpcKeygen(config);
    }

    return config;
  }

  /**
   * Encrypt a plaintext value using the TFHE public key.
   * This can be done entirely on the KMS side without MPC.
   */
  async encrypt(keyId: string, plaintext: bigint): Promise<EncryptedValue> {
    const config = this.requireKey(keyId);
    const pubKey = this.publicKeys.get(keyId);
    if (!pubKey) throw new Error("tfhe: public key not loaded");

    // In production, this calls the luxfi/fhe library via WASM or FFI
    // For now, we create a tagged ciphertext structure
    const plaintextBuf = Buffer.alloc(8);
    plaintextBuf.writeBigUInt64BE(plaintext);

    // TFHE encryption: FHE.encrypt(plaintext, pubKey) → ciphertext
    // This is a placeholder - real impl uses luxfi/fhe TFHE encryption
    const ciphertext = this.fheEncrypt(plaintextBuf, pubKey, config.keyType);

    return {
      ciphertext,
      keyId,
      keyType: config.keyType,
      generation: config.generation
    };
  }

  /**
   * Request threshold decryption via MPC cluster.
   * Requires t-of-n parties to provide decryption shares.
   */
  async requestDecryption(keyId: string, encryptedValue: EncryptedValue): Promise<DecryptionShareRequest> {
    const config = this.requireKey(keyId);

    return {
      keyId,
      ciphertext: encryptedValue.ciphertext,
      partyId: -1 // assigned by MPC coordinator
    };
  }

  /**
   * Combine decryption shares to recover plaintext.
   * Must have at least `threshold` shares.
   */
  combineDecryptionShares(keyId: string, shares: DecryptionShare[]): Buffer {
    const config = this.requireKey(keyId);

    if (shares.length < config.threshold) {
      throw new Error(`tfhe: need ${config.threshold} shares, got ${shares.length}`);
    }

    // In production, this uses luxfi/fhe threshold decryption combiner
    // Placeholder: XOR shares together (real impl uses Lagrange interpolation on FHE shares)
    return this.fheCombineShares(shares);
  }

  /**
   * Evaluate a private policy rule on encrypted transaction data.
   * Used by MPC ThresholdVM for TFHE policy enforcement.
   */
  async evaluatePrivatePolicy(
    rule: PrivatePolicyRule,
    encryptedAmount: EncryptedValue,
    policyState: EncryptedPolicyState
  ): Promise<EncryptedValue> {
    const config = this.requireKey(encryptedAmount.keyId);

    // These operations run on encrypted data - no plaintext exposure
    // In production, calls into luxfi/fhe homomorphic operations
    switch (rule.opcode) {
      case 0x80: // PrivateAmountLT
        return this.fheCompute({
          operation: TfheOperation.Lt,
          keyId: encryptedAmount.keyId,
          operands: [encryptedAmount, rule.encryptedThreshold!]
        });

      case 0x81: // PrivateAmountGT
        return this.fheCompute({
          operation: TfheOperation.Gt,
          keyId: encryptedAmount.keyId,
          operands: [encryptedAmount, rule.encryptedThreshold!]
        });

      case 0x82: // PrivateCumulative
        // cumulative_daily + amount < threshold
        const newCumulative = await this.fheCompute({
          operation: TfheOperation.Add,
          keyId: encryptedAmount.keyId,
          operands: [policyState.cumulativeDaily, encryptedAmount]
        });
        return this.fheCompute({
          operation: TfheOperation.Lt,
          keyId: encryptedAmount.keyId,
          operands: [newCumulative, rule.encryptedThreshold!]
        });

      case 0x83: // PrivateWhitelist
        // Check if encrypted destination is in encrypted whitelist
        if (!rule.encryptedWhitelist?.length) {
          return this.fheTrivialEncrypt(encryptedAmount.keyId, BigInt(0)); // false
        }
        let result = await this.fheCompute({
          operation: TfheOperation.Eq,
          keyId: encryptedAmount.keyId,
          operands: [encryptedAmount, rule.encryptedWhitelist[0]]
        });
        for (let i = 1; i < rule.encryptedWhitelist.length; i++) {
          const eq = await this.fheCompute({
            operation: TfheOperation.Eq,
            keyId: encryptedAmount.keyId,
            operands: [encryptedAmount, rule.encryptedWhitelist[i]]
          });
          result = await this.fheCompute({
            operation: TfheOperation.Or,
            keyId: encryptedAmount.keyId,
            operands: [result, eq]
          });
        }
        return result;

      default:
        throw new Error(`tfhe: unsupported private policy opcode: 0x${rule.opcode.toString(16)}`);
    }
  }

  /**
   * Update encrypted policy state after a transaction.
   */
  async updatePolicyState(
    state: EncryptedPolicyState,
    amount: EncryptedValue,
    timestamp: EncryptedValue
  ): Promise<EncryptedPolicyState> {
    return {
      cumulativeDaily: await this.fheCompute({
        operation: TfheOperation.Add,
        keyId: amount.keyId,
        operands: [state.cumulativeDaily, amount]
      }),
      cumulativeMonthly: await this.fheCompute({
        operation: TfheOperation.Add,
        keyId: amount.keyId,
        operands: [state.cumulativeMonthly, amount]
      }),
      lastTxTime: timestamp,
      vestedAmount: state.vestedAmount,
      streamedAmount: state.streamedAmount
    };
  }

  /**
   * Store a public key after MPC keygen completes
   */
  setPublicKey(keyId: string, publicKey: Buffer): void {
    const config = this.keys.get(keyId);
    if (config) {
      config.status = "active";
      config.updatedAt = new Date();
    }
    this.publicKeys.set(keyId, publicKey);
  }

  getKey(keyId: string): TfheKeyConfig | undefined {
    return this.keys.get(keyId);
  }

  listKeys(): TfheKeyConfig[] {
    return Array.from(this.keys.values());
  }

  // --- Internal FHE operations (placeholders for luxfi/fhe integration) ---

  private fheEncrypt(plaintext: Buffer, publicKey: Buffer, keyType: FheKeyType): Buffer {
    // Production: calls luxfi/fhe TFHE.Encrypt(plaintext, publicKey)
    // Tag format: [magic (4)] [keyType (1)] [nonce (16)] [encrypted (var)]
    const magic = Buffer.from("TFHE");
    const typeTag = Buffer.from([Object.values(FheKeyType).indexOf(keyType)]);
    const nonce = crypto.randomBytes(16);
    // Simulated encryption: AES-GCM with derived key from public key hash
    const encKey = crypto.createHash("sha256").update(publicKey).digest();
    const cipher = crypto.createCipheriv("aes-256-gcm", encKey, nonce.subarray(0, 12));
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([magic, typeTag, nonce, tag, encrypted]);
  }

  private fheCompute(req: TfheComputeRequest): Promise<EncryptedValue> {
    // Production: calls luxfi/fhe server key operations
    // The MPC cluster has the server key (evaluation key) distributed
    // Operations: Add, Sub, Mul, Lt, Gt, Eq, And, Or, Not, Select
    return Promise.resolve({
      ciphertext: Buffer.concat(req.operands.map((o) => o.ciphertext)),
      keyId: req.keyId,
      keyType: req.operands[0]?.keyType ?? FheKeyType.TFHE_UINT64,
      generation: req.operands[0]?.generation ?? 1
    });
  }

  private fheTrivialEncrypt(keyId: string, value: bigint): Promise<EncryptedValue> {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(value);
    return Promise.resolve({
      ciphertext: buf,
      keyId,
      keyType: FheKeyType.TFHE_BOOL,
      generation: 1
    });
  }

  private fheCombineShares(shares: DecryptionShare[]): Buffer {
    // Production: Lagrange interpolation on TFHE decryption shares
    if (shares.length === 0) throw new Error("tfhe: no shares to combine");
    return shares[0].share; // Placeholder
  }

  private async triggerMpcKeygen(config: TfheKeyConfig): Promise<void> {
    if (!this.mpcEndpoint) return;

    // Production: POST to MPC API or publish to NATS JetStream
    // mpc.keygen_request.{walletId} with TFHE keygen parameters
    try {
      const response = await fetch(`${this.mpcEndpoint}/api/v1/wallets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          walletId: config.walletId,
          keyType: "tfhe",
          threshold: config.threshold,
          totalParties: config.totalParties,
          fheKeyType: config.keyType
        })
      });

      if (response.ok) {
        config.status = "active";
        config.updatedAt = new Date();
      }
    } catch {
      // Keygen may complete asynchronously via NATS callback
    }
  }

  private requireKey(keyId: string): TfheKeyConfig {
    const config = this.keys.get(keyId);
    if (!config) throw new Error(`tfhe: key "${keyId}" not found`);
    if (config.status === "revoked") throw new Error(`tfhe: key "${keyId}" is revoked`);
    return config;
  }
}
