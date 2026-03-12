import crypto from "node:crypto";

import {
  HashAlgorithm,
  MarshalingType,
  TransitKeyType,
  type TransitKeyVersion
} from "./transit-types";

const IV_SIZE = 12;
const AUTH_TAG_SIZE = 16;

/**
 * Derive a per-operation key from a master key + context using HKDF
 */
export function deriveKey(masterKey: Buffer, context: Buffer, keyLen: number): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), context, keyLen));
}

/**
 * AES-256-GCM encryption with optional AAD
 */
export function encryptAES256GCM(key: Buffer, plaintext: Buffer, aad?: Buffer): Buffer {
  const iv = crypto.randomBytes(IV_SIZE);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(aad);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Format: [iv (12)] [tag (16)] [ciphertext]
  return Buffer.concat([iv, tag, encrypted]);
}

/**
 * AES-256-GCM decryption with optional AAD
 */
export function decryptAES256GCM(key: Buffer, data: Buffer, aad?: Buffer): Buffer {
  if (data.length < IV_SIZE + AUTH_TAG_SIZE) {
    throw new Error("transit: ciphertext too short");
  }

  const iv = data.subarray(0, IV_SIZE);
  const tag = data.subarray(IV_SIZE, IV_SIZE + AUTH_TAG_SIZE);
  const ciphertext = data.subarray(IV_SIZE + AUTH_TAG_SIZE);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * AES-128-GCM encryption
 */
export function encryptAES128GCM(key: Buffer, plaintext: Buffer, aad?: Buffer): Buffer {
  const iv = crypto.randomBytes(IV_SIZE);
  const cipher = crypto.createCipheriv("aes-128-gcm", key.subarray(0, 16), iv);
  if (aad) cipher.setAAD(aad);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]);
}

export function decryptAES128GCM(key: Buffer, data: Buffer, aad?: Buffer): Buffer {
  if (data.length < IV_SIZE + AUTH_TAG_SIZE) {
    throw new Error("transit: ciphertext too short");
  }

  const iv = data.subarray(0, IV_SIZE);
  const tag = data.subarray(IV_SIZE, IV_SIZE + AUTH_TAG_SIZE);
  const ciphertext = data.subarray(IV_SIZE + AUTH_TAG_SIZE);

  const decipher = crypto.createDecipheriv("aes-128-gcm", key.subarray(0, 16), iv);
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * ChaCha20-Poly1305 encryption
 */
export function encryptChaCha20(key: Buffer, plaintext: Buffer, aad?: Buffer): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("chacha20-poly1305" as crypto.CipherGCMTypes, key, iv, {
    authTagLength: 16
  });
  if (aad) cipher.setAAD(aad);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]);
}

export function decryptChaCha20(key: Buffer, data: Buffer, aad?: Buffer): Buffer {
  if (data.length < 12 + 16) {
    throw new Error("transit: ciphertext too short");
  }

  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);

  const decipher = crypto.createDecipheriv("chacha20-poly1305" as crypto.CipherGCMTypes, key, iv, {
    authTagLength: 16
  });
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Generate key material for a given key type
 */
export function generateKeyMaterial(type: TransitKeyType): TransitKeyVersion {
  const now = new Date();

  switch (type) {
    case TransitKeyType.AES256GCM96:
      return { version: 1, key: crypto.randomBytes(32), creationTime: now };

    case TransitKeyType.AES128GCM96:
      return { version: 1, key: crypto.randomBytes(16), creationTime: now };

    case TransitKeyType.ChaCha20Poly1305:
      return { version: 1, key: crypto.randomBytes(32), creationTime: now };

    case TransitKeyType.HMAC:
      return { version: 1, key: crypto.randomBytes(32), hmacKey: crypto.randomBytes(32), creationTime: now };

    case TransitKeyType.Ed25519: {
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
      return {
        version: 1,
        key: Buffer.alloc(0),
        publicKey: publicKey.export({ type: "spki", format: "der" }) as Buffer,
        privateKey: privateKey.export({ type: "pkcs8", format: "der" }) as Buffer,
        creationTime: now
      };
    }

    case TransitKeyType.ECDSA_P256: {
      const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      return {
        version: 1,
        key: Buffer.alloc(0),
        publicKey: pair.publicKey.export({ type: "spki", format: "der" }) as Buffer,
        privateKey: pair.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer,
        creationTime: now
      };
    }

    case TransitKeyType.ECDSA_P384: {
      const pair = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
      return {
        version: 1,
        key: Buffer.alloc(0),
        publicKey: pair.publicKey.export({ type: "spki", format: "der" }) as Buffer,
        privateKey: pair.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer,
        creationTime: now
      };
    }

    case TransitKeyType.RSA2048: {
      const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
      return {
        version: 1,
        key: Buffer.alloc(0),
        publicKey: pair.publicKey.export({ type: "spki", format: "der" }) as Buffer,
        privateKey: pair.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer,
        creationTime: now
      };
    }

    case TransitKeyType.RSA3072: {
      const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
      return {
        version: 1,
        key: Buffer.alloc(0),
        publicKey: pair.publicKey.export({ type: "spki", format: "der" }) as Buffer,
        privateKey: pair.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer,
        creationTime: now
      };
    }

    case TransitKeyType.RSA4096: {
      const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });
      return {
        version: 1,
        key: Buffer.alloc(0),
        publicKey: pair.publicKey.export({ type: "spki", format: "der" }) as Buffer,
        privateKey: pair.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer,
        creationTime: now
      };
    }

    default:
      throw new Error(`transit: unsupported key type: ${type}`);
  }
}

/**
 * Encrypt plaintext using the appropriate algorithm for the key type
 */
export function transitEncrypt(
  keyVersion: TransitKeyVersion,
  type: TransitKeyType,
  plaintext: Buffer,
  context?: Buffer,
  aad?: Buffer,
  derived = false
): Buffer {
  let key = keyVersion.key;

  if (derived && context) {
    const keyLen = type === TransitKeyType.AES128GCM96 ? 16 : 32;
    key = deriveKey(key, context, keyLen);
  }

  switch (type) {
    case TransitKeyType.AES256GCM96:
      return encryptAES256GCM(key, plaintext, aad);
    case TransitKeyType.AES128GCM96:
      return encryptAES128GCM(key, plaintext, aad);
    case TransitKeyType.ChaCha20Poly1305:
      return encryptChaCha20(key, plaintext, aad);
    case TransitKeyType.RSA2048:
    case TransitKeyType.RSA3072:
    case TransitKeyType.RSA4096: {
      const pubKey = crypto.createPublicKey({ key: keyVersion.publicKey!, format: "der", type: "spki" });
      return crypto.publicEncrypt({ key: pubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, plaintext);
    }
    default:
      throw new Error(`transit: key type ${type} does not support encryption`);
  }
}

/**
 * Decrypt ciphertext using the appropriate algorithm for the key type
 */
export function transitDecrypt(
  keyVersion: TransitKeyVersion,
  type: TransitKeyType,
  ciphertext: Buffer,
  context?: Buffer,
  aad?: Buffer,
  derived = false
): Buffer {
  let key = keyVersion.key;

  if (derived && context) {
    const keyLen = type === TransitKeyType.AES128GCM96 ? 16 : 32;
    key = deriveKey(key, context, keyLen);
  }

  switch (type) {
    case TransitKeyType.AES256GCM96:
      return decryptAES256GCM(key, ciphertext, aad);
    case TransitKeyType.AES128GCM96:
      return decryptAES128GCM(key, ciphertext, aad);
    case TransitKeyType.ChaCha20Poly1305:
      return decryptChaCha20(key, ciphertext, aad);
    case TransitKeyType.RSA2048:
    case TransitKeyType.RSA3072:
    case TransitKeyType.RSA4096: {
      const privKey = crypto.createPrivateKey({ key: keyVersion.privateKey!, format: "der", type: "pkcs8" });
      return crypto.privateDecrypt({ key: privKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, ciphertext);
    }
    default:
      throw new Error(`transit: key type ${type} does not support decryption`);
  }
}

/**
 * Sign data with the appropriate algorithm
 */
export function transitSign(
  keyVersion: TransitKeyVersion,
  type: TransitKeyType,
  data: Buffer,
  hashAlg: HashAlgorithm = HashAlgorithm.SHA256,
  prehashed = false
): Buffer {
  const privKey = crypto.createPrivateKey({ key: keyVersion.privateKey!, format: "der", type: "pkcs8" });

  switch (type) {
    case TransitKeyType.Ed25519:
      return crypto.sign(null, data, privKey);

    case TransitKeyType.ECDSA_P256:
    case TransitKeyType.ECDSA_P384: {
      const input = prehashed ? data : data;
      return crypto.sign(hashAlg, input, privKey);
    }

    case TransitKeyType.RSA2048:
    case TransitKeyType.RSA3072:
    case TransitKeyType.RSA4096: {
      return crypto.sign(hashAlg, data, {
        key: privKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      });
    }

    default:
      throw new Error(`transit: key type ${type} does not support signing`);
  }
}

/**
 * Verify a signature
 */
export function transitVerify(
  keyVersion: TransitKeyVersion,
  type: TransitKeyType,
  data: Buffer,
  signature: Buffer,
  hashAlg: HashAlgorithm = HashAlgorithm.SHA256
): boolean {
  const pubKey = crypto.createPublicKey({ key: keyVersion.publicKey!, format: "der", type: "spki" });

  switch (type) {
    case TransitKeyType.Ed25519:
      return crypto.verify(null, data, pubKey, signature);

    case TransitKeyType.ECDSA_P256:
    case TransitKeyType.ECDSA_P384:
      return crypto.verify(hashAlg, data, pubKey, signature);

    case TransitKeyType.RSA2048:
    case TransitKeyType.RSA3072:
    case TransitKeyType.RSA4096:
      return crypto.verify(hashAlg, data, {
        key: pubKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      }, signature);

    default:
      throw new Error(`transit: key type ${type} does not support verification`);
  }
}

/**
 * Compute HMAC
 */
export function transitHmac(key: Buffer, data: Buffer, algorithm: HashAlgorithm = HashAlgorithm.SHA256): Buffer {
  return crypto.createHmac(algorithm, key).update(data).digest();
}

/**
 * Hash data (no key needed)
 */
export function transitHash(data: Buffer, algorithm: HashAlgorithm = HashAlgorithm.SHA256): Buffer {
  return crypto.createHash(algorithm).update(data).digest();
}

/**
 * Generate random bytes
 */
export function transitRandom(bytes: number): Buffer {
  return crypto.randomBytes(bytes);
}
