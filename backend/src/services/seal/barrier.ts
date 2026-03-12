import crypto from "node:crypto";

import type { BarrierKeyring } from "./seal-types";

const IV_SIZE = 12;
const TAG_SIZE = 16;
const TERM_SIZE = 4; // uint32 term prefix

/**
 * AES-256-GCM encryption barrier.
 * All data passes through this barrier before hitting storage.
 * Supports key rotation via a keyring with versioned terms.
 */
export class Barrier {
  private keyring: BarrierKeyring;
  private sealed = true;

  constructor() {
    this.keyring = { activeTerm: 0, keys: new Map() };
  }

  get isSealed(): boolean {
    return this.sealed;
  }

  /**
   * Initialize the barrier with a root key, creating term 1
   */
  initialize(rootKey: Buffer): void {
    if (rootKey.length !== 32) {
      throw new Error("barrier: root key must be 32 bytes");
    }
    this.keyring.keys.set(1, rootKey);
    this.keyring.activeTerm = 1;
    this.sealed = false;
  }

  /**
   * Unseal with a previously initialized root key
   */
  unseal(rootKey: Buffer): void {
    if (rootKey.length !== 32) {
      throw new Error("barrier: root key must be 32 bytes");
    }
    if (this.keyring.keys.size === 0) {
      this.keyring.keys.set(1, rootKey);
      this.keyring.activeTerm = 1;
    }
    this.sealed = false;
  }

  /**
   * Seal the barrier, clearing all keys from memory
   */
  seal(): void {
    // Zero out key material
    for (const key of this.keyring.keys.values()) {
      key.fill(0);
    }
    this.keyring.keys.clear();
    this.keyring.activeTerm = 0;
    this.sealed = true;
  }

  /**
   * Rotate to a new key term
   */
  rotate(): number {
    this.requireUnsealed();
    const newTerm = this.keyring.activeTerm + 1;
    const newKey = crypto.randomBytes(32);
    this.keyring.keys.set(newTerm, newKey);
    this.keyring.activeTerm = newTerm;
    return newTerm;
  }

  /**
   * Encrypt data with the active key term.
   * Format: [term (4 bytes)] [iv (12)] [tag (16)] [ciphertext]
   */
  encrypt(plaintext: Buffer): Buffer {
    this.requireUnsealed();
    const key = this.keyring.keys.get(this.keyring.activeTerm);
    if (!key) throw new Error("barrier: no active key");

    const iv = crypto.randomBytes(IV_SIZE);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Prepend term number for key versioning
    const termBuf = Buffer.alloc(TERM_SIZE);
    termBuf.writeUInt32BE(this.keyring.activeTerm);

    return Buffer.concat([termBuf, iv, tag, encrypted]);
  }

  /**
   * Decrypt data, looking up the key by term
   */
  decrypt(data: Buffer): Buffer {
    this.requireUnsealed();

    if (data.length < TERM_SIZE + IV_SIZE + TAG_SIZE) {
      throw new Error("barrier: data too short");
    }

    const term = data.readUInt32BE(0);
    const iv = data.subarray(TERM_SIZE, TERM_SIZE + IV_SIZE);
    const tag = data.subarray(TERM_SIZE + IV_SIZE, TERM_SIZE + IV_SIZE + TAG_SIZE);
    const ciphertext = data.subarray(TERM_SIZE + IV_SIZE + TAG_SIZE);

    const key = this.keyring.keys.get(term);
    if (!key) throw new Error(`barrier: key term ${term} not found`);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * Re-encrypt data with the current active term
   */
  rekey(data: Buffer): Buffer {
    const plaintext = this.decrypt(data);
    return this.encrypt(plaintext);
  }

  get activeTerm(): number {
    return this.keyring.activeTerm;
  }

  private requireUnsealed(): void {
    if (this.sealed) throw new Error("barrier: sealed");
  }
}
