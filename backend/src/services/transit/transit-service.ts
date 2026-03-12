import crypto from "node:crypto";

import {
  type BatchItem,
  HashAlgorithm,
  type TransitDataKeyRequest,
  type TransitDataKeyResponse,
  type TransitDecryptRequest,
  type TransitDecryptResponse,
  type TransitEncryptRequest,
  type TransitEncryptResponse,
  type TransitHmacRequest,
  type TransitKeyInfo,
  type TransitKeyPolicy,
  TransitKeyType,
  type TransitKeyVersion,
  type TransitRewrapRequest,
  type TransitSignRequest,
  type TransitSignResponse,
  type TransitVerifyRequest,
  isSymmetric,
  supportsDerivation,
  supportsEncryption,
  supportsSigning
} from "./transit-types";
import {
  generateKeyMaterial,
  transitDecrypt,
  transitEncrypt,
  transitHash,
  transitHmac,
  transitRandom,
  transitSign,
  transitVerify
} from "./transit-crypto";

const CIPHERTEXT_PREFIX = "hanzo:v";
const SIGNATURE_PREFIX = "hanzo:v";
const HMAC_PREFIX = "hanzo:v";

/**
 * In-memory Transit Engine service.
 * Production: back with PostgreSQL via existing KMS DAL patterns.
 */
export class TransitService {
  private policies = new Map<string, TransitKeyPolicy>();
  private autoRotateTimer?: ReturnType<typeof setInterval>;

  constructor() {
    // Check auto-rotation every 60 seconds
    this.autoRotateTimer = setInterval(() => this.checkAutoRotation(), 60_000);
  }

  destroy(): void {
    if (this.autoRotateTimer) {
      clearInterval(this.autoRotateTimer);
    }
  }

  // --- Key Management ---

  createKey(
    name: string,
    type: TransitKeyType = TransitKeyType.AES256GCM96,
    options: {
      derived?: boolean;
      convergentEncryption?: boolean;
      exportable?: boolean;
      allowPlaintextBackup?: boolean;
      autoRotatePeriod?: number;
    } = {}
  ): TransitKeyInfo {
    if (this.policies.has(name)) {
      throw new Error(`transit: key "${name}" already exists`);
    }

    if (options.convergentEncryption && !options.derived) {
      throw new Error("transit: convergent encryption requires derived mode");
    }

    if (options.derived && !supportsDerivation(type)) {
      throw new Error(`transit: key type ${type} does not support derivation`);
    }

    const keyVersion = generateKeyMaterial(type);
    keyVersion.version = 1;

    const policy: TransitKeyPolicy = {
      name,
      type,
      derived: options.derived ?? false,
      convergentEncryption: options.convergentEncryption ?? false,
      exportable: options.exportable ?? false,
      allowPlaintextBackup: options.allowPlaintextBackup ?? false,
      minDecryptionVersion: 1,
      minEncryptionVersion: 0,
      latestVersion: 1,
      autoRotatePeriod: options.autoRotatePeriod ?? 0,
      deletionAllowed: false,
      keys: new Map([[1, keyVersion]]),
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.policies.set(name, policy);
    return this.getKeyInfo(name)!;
  }

  rotateKey(name: string): TransitKeyInfo {
    const policy = this.requirePolicy(name);
    const newVersion = policy.latestVersion + 1;
    const keyVersion = generateKeyMaterial(policy.type);
    keyVersion.version = newVersion;

    policy.keys.set(newVersion, keyVersion);
    policy.latestVersion = newVersion;
    policy.updatedAt = new Date();

    return this.getKeyInfo(name)!;
  }

  configureKey(
    name: string,
    config: {
      minDecryptionVersion?: number;
      minEncryptionVersion?: number;
      deletionAllowed?: boolean;
      exportable?: boolean;
      allowPlaintextBackup?: boolean;
      autoRotatePeriod?: number;
    }
  ): void {
    const policy = this.requirePolicy(name);

    if (config.minDecryptionVersion !== undefined) {
      if (config.minDecryptionVersion < 1 || config.minDecryptionVersion > policy.latestVersion) {
        throw new Error(`transit: minDecryptionVersion must be between 1 and ${policy.latestVersion}`);
      }
      policy.minDecryptionVersion = config.minDecryptionVersion;
    }
    if (config.minEncryptionVersion !== undefined) {
      if (config.minEncryptionVersion > policy.latestVersion) {
        throw new Error(`transit: minEncryptionVersion cannot exceed latest version`);
      }
      policy.minEncryptionVersion = config.minEncryptionVersion;
    }
    if (config.deletionAllowed !== undefined) policy.deletionAllowed = config.deletionAllowed;
    if (config.exportable === true) policy.exportable = true; // one-way flag
    if (config.allowPlaintextBackup === true) policy.allowPlaintextBackup = true;
    if (config.autoRotatePeriod !== undefined) {
      if (config.autoRotatePeriod > 0 && config.autoRotatePeriod < 3600) {
        throw new Error("transit: autoRotatePeriod must be at least 1 hour (3600s)");
      }
      policy.autoRotatePeriod = config.autoRotatePeriod;
    }

    policy.updatedAt = new Date();
  }

  deleteKey(name: string): void {
    const policy = this.requirePolicy(name);
    if (!policy.deletionAllowed) {
      throw new Error(`transit: deletion not allowed for key "${name}"`);
    }
    this.policies.delete(name);
  }

  getKeyInfo(name: string): TransitKeyInfo | undefined {
    const policy = this.policies.get(name);
    if (!policy) return undefined;

    const keys: Record<number, { creationTime: string; publicKey?: string }> = {};
    for (const [v, kv] of policy.keys) {
      if (v >= policy.minDecryptionVersion) {
        keys[v] = {
          creationTime: kv.creationTime.toISOString(),
          ...(kv.publicKey ? { publicKey: kv.publicKey.toString("base64") } : {})
        };
      }
    }

    return {
      name: policy.name,
      type: policy.type,
      derived: policy.derived,
      convergentEncryption: policy.convergentEncryption,
      exportable: policy.exportable,
      allowPlaintextBackup: policy.allowPlaintextBackup,
      deletionAllowed: policy.deletionAllowed,
      minDecryptionVersion: policy.minDecryptionVersion,
      minEncryptionVersion: policy.minEncryptionVersion,
      latestVersion: policy.latestVersion,
      autoRotatePeriod: policy.autoRotatePeriod,
      supportsEncryption: supportsEncryption(policy.type),
      supportsSigning: supportsSigning(policy.type),
      supportsDerivation: supportsDerivation(policy.type),
      keys
    };
  }

  listKeys(): string[] {
    return Array.from(this.policies.keys()).sort();
  }

  exportKey(name: string, keyType: "encryption-key" | "signing-key" | "hmac-key" | "public-key", version?: number): Record<number, string> {
    const policy = this.requirePolicy(name);

    if (keyType !== "public-key" && !policy.exportable) {
      throw new Error(`transit: key "${name}" is not exportable`);
    }

    const result: Record<number, string> = {};
    const versions = version
      ? [version]
      : Array.from(policy.keys.keys()).filter((v) => v >= policy.minDecryptionVersion);

    for (const v of versions) {
      const kv = policy.keys.get(v);
      if (!kv) throw new Error(`transit: key version ${v} not found`);

      switch (keyType) {
        case "encryption-key":
          if (!isSymmetric(policy.type)) throw new Error("transit: not a symmetric key");
          result[v] = kv.key.toString("base64");
          break;
        case "signing-key":
          if (!kv.privateKey) throw new Error("transit: no private key");
          result[v] = kv.privateKey.toString("base64");
          break;
        case "hmac-key":
          result[v] = (kv.hmacKey || kv.key).toString("base64");
          break;
        case "public-key":
          if (!kv.publicKey) throw new Error("transit: no public key");
          result[v] = kv.publicKey.toString("base64");
          break;
      }
    }

    return result;
  }

  // --- Encrypt / Decrypt / Rewrap ---

  encrypt(req: TransitEncryptRequest): TransitEncryptResponse {
    const policy = this.requirePolicy(req.keyName);
    if (!supportsEncryption(policy.type)) {
      throw new Error(`transit: key type ${policy.type} does not support encryption`);
    }

    const version = req.keyVersion || policy.latestVersion;
    if (policy.minEncryptionVersion > 0 && version < policy.minEncryptionVersion) {
      throw new Error(`transit: key version ${version} below minimum encryption version`);
    }

    const kv = policy.keys.get(version);
    if (!kv) throw new Error(`transit: key version ${version} not found`);

    const plaintext = Buffer.from(req.plaintext, "base64");
    const context = req.context ? Buffer.from(req.context, "base64") : undefined;
    const aad = req.associatedData ? Buffer.from(req.associatedData, "base64") : undefined;

    const encrypted = transitEncrypt(kv, policy.type, plaintext, context, aad, policy.derived);
    return {
      ciphertext: `${CIPHERTEXT_PREFIX}${version}:${encrypted.toString("base64")}`,
      keyVersion: version
    };
  }

  decrypt(req: TransitDecryptRequest): TransitDecryptResponse {
    const policy = this.requirePolicy(req.keyName);
    if (!supportsEncryption(policy.type)) {
      throw new Error(`transit: key type ${policy.type} does not support decryption`);
    }

    const { version, data } = this.parsePrefixed(req.ciphertext);
    if (version < policy.minDecryptionVersion) {
      throw new Error(`transit: ciphertext version ${version} below minimum decryption version`);
    }

    const kv = policy.keys.get(version);
    if (!kv) throw new Error(`transit: key version ${version} not found`);

    const context = req.context ? Buffer.from(req.context, "base64") : undefined;
    const aad = req.associatedData ? Buffer.from(req.associatedData, "base64") : undefined;

    const plaintext = transitDecrypt(kv, policy.type, data, context, aad, policy.derived);
    return { plaintext: plaintext.toString("base64") };
  }

  rewrap(req: TransitRewrapRequest): TransitEncryptResponse {
    const policy = this.requirePolicy(req.keyName);

    // Decrypt with old version
    const { version: oldVersion, data: ciphertext } = this.parsePrefixed(req.ciphertext);
    if (oldVersion < policy.minDecryptionVersion) {
      throw new Error(`transit: ciphertext version ${oldVersion} below minimum decryption version`);
    }

    const oldKv = policy.keys.get(oldVersion);
    if (!oldKv) throw new Error(`transit: key version ${oldVersion} not found`);

    const context = req.context ? Buffer.from(req.context, "base64") : undefined;
    const aad = req.associatedData ? Buffer.from(req.associatedData, "base64") : undefined;

    const plaintext = transitDecrypt(oldKv, policy.type, ciphertext, context, aad, policy.derived);

    // Re-encrypt with target version (default: latest)
    const newVersion = req.keyVersion || policy.latestVersion;
    const newKv = policy.keys.get(newVersion);
    if (!newKv) throw new Error(`transit: key version ${newVersion} not found`);

    const reEncrypted = transitEncrypt(newKv, policy.type, plaintext, context, aad, policy.derived);

    return {
      ciphertext: `${CIPHERTEXT_PREFIX}${newVersion}:${reEncrypted.toString("base64")}`,
      keyVersion: newVersion
    };
  }

  // --- Sign / Verify ---

  sign(req: TransitSignRequest): TransitSignResponse {
    const policy = this.requirePolicy(req.keyName);
    if (!supportsSigning(policy.type)) {
      throw new Error(`transit: key type ${policy.type} does not support signing`);
    }

    const version = req.keyVersion || policy.latestVersion;
    const kv = policy.keys.get(version);
    if (!kv) throw new Error(`transit: key version ${version} not found`);

    const input = Buffer.from(req.input, "base64");
    const hashAlg = req.hashAlgorithm || HashAlgorithm.SHA256;

    const sig = transitSign(kv, policy.type, input, hashAlg, req.prehashed);
    return {
      signature: `${SIGNATURE_PREFIX}${version}:${sig.toString("base64")}`,
      publicKey: kv.publicKey?.toString("base64")
    };
  }

  verify(req: TransitVerifyRequest): boolean {
    const policy = this.requirePolicy(req.keyName);
    if (!supportsSigning(policy.type)) {
      throw new Error(`transit: key type ${policy.type} does not support verification`);
    }

    const { version, data: signature } = this.parsePrefixed(req.signature);
    if (version < policy.minDecryptionVersion) {
      throw new Error(`transit: signature version ${version} below minimum version`);
    }

    const kv = policy.keys.get(version);
    if (!kv) throw new Error(`transit: key version ${version} not found`);

    const input = Buffer.from(req.input, "base64");
    const hashAlg = req.hashAlgorithm || HashAlgorithm.SHA256;

    return transitVerify(kv, policy.type, input, signature, hashAlg);
  }

  // --- HMAC / Hash / Random / DataKey ---

  hmac(req: TransitHmacRequest): string {
    const policy = this.requirePolicy(req.keyName);
    const version = req.keyVersion || policy.latestVersion;
    const kv = policy.keys.get(version);
    if (!kv) throw new Error(`transit: key version ${version} not found`);

    const key = kv.hmacKey || kv.key;
    const input = Buffer.from(req.input, "base64");
    const alg = req.algorithm || HashAlgorithm.SHA256;

    const result = transitHmac(key, input, alg);
    return `${HMAC_PREFIX}${version}:${result.toString("base64")}`;
  }

  hash(input: string, algorithm: HashAlgorithm = HashAlgorithm.SHA256): string {
    const data = Buffer.from(input, "base64");
    return transitHash(data, algorithm).toString("base64");
  }

  random(bytes: number = 32, format: "base64" | "hex" = "base64"): string {
    const buf = transitRandom(bytes);
    return format === "hex" ? buf.toString("hex") : buf.toString("base64");
  }

  generateDataKey(req: TransitDataKeyRequest, returnPlaintext: boolean): TransitDataKeyResponse {
    const policy = this.requirePolicy(req.keyName);
    if (!supportsEncryption(policy.type)) {
      throw new Error(`transit: key type ${policy.type} does not support data key generation`);
    }

    const bits = req.bits || 256;
    const plaintext = crypto.randomBytes(bits / 8);

    const kv = policy.keys.get(policy.latestVersion)!;
    const context = req.context ? Buffer.from(req.context, "base64") : undefined;

    const encrypted = transitEncrypt(kv, policy.type, plaintext, context, undefined, policy.derived);
    const ciphertext = `${CIPHERTEXT_PREFIX}${policy.latestVersion}:${encrypted.toString("base64")}`;

    return {
      ciphertext,
      keyVersion: policy.latestVersion,
      ...(returnPlaintext ? { plaintext: plaintext.toString("base64") } : {})
    };
  }

  // --- Batch Operations ---

  batchEncrypt(keyName: string, items: TransitEncryptRequest[]): BatchItem<TransitEncryptResponse>[] {
    return items.map((item) => {
      try {
        return { data: this.encrypt({ ...item, keyName }), reference: (item as any).reference };
      } catch (err: any) {
        return { data: {} as TransitEncryptResponse, error: err.message, reference: (item as any).reference };
      }
    });
  }

  batchDecrypt(keyName: string, items: TransitDecryptRequest[]): BatchItem<TransitDecryptResponse>[] {
    return items.map((item) => {
      try {
        return { data: this.decrypt({ ...item, keyName }), reference: (item as any).reference };
      } catch (err: any) {
        return { data: {} as TransitDecryptResponse, error: err.message, reference: (item as any).reference };
      }
    });
  }

  batchRewrap(keyName: string, items: TransitRewrapRequest[]): BatchItem<TransitEncryptResponse>[] {
    return items.map((item) => {
      try {
        return { data: this.rewrap({ ...item, keyName }), reference: (item as any).reference };
      } catch (err: any) {
        return { data: {} as TransitEncryptResponse, error: err.message, reference: (item as any).reference };
      }
    });
  }

  // --- Internals ---

  private requirePolicy(name: string): TransitKeyPolicy {
    const policy = this.policies.get(name);
    if (!policy) throw new Error(`transit: key "${name}" not found`);
    return policy;
  }

  private parsePrefixed(value: string): { version: number; data: Buffer } {
    const match = value.match(/^hanzo:v(\d+):(.+)$/);
    if (!match) throw new Error("transit: invalid ciphertext/signature format, expected hanzo:v{N}:{data}");
    return {
      version: parseInt(match[1], 10),
      data: Buffer.from(match[2], "base64")
    };
  }

  private checkAutoRotation(): void {
    const now = Date.now();
    for (const [, policy] of this.policies) {
      if (policy.autoRotatePeriod <= 0) continue;

      const latestKey = policy.keys.get(policy.latestVersion);
      if (!latestKey) continue;

      const elapsed = (now - latestKey.creationTime.getTime()) / 1000;
      if (elapsed >= policy.autoRotatePeriod) {
        try {
          this.rotateKey(policy.name);
        } catch {
          // Log but don't crash on auto-rotation failures
        }
      }
    }
  }
}
