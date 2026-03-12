export enum TransitKeyType {
  AES256GCM96 = "aes256-gcm96",
  AES128GCM96 = "aes128-gcm96",
  ChaCha20Poly1305 = "chacha20-poly1305",
  Ed25519 = "ed25519",
  ECDSA_P256 = "ecdsa-p256",
  ECDSA_P384 = "ecdsa-p384",
  RSA2048 = "rsa-2048",
  RSA3072 = "rsa-3072",
  RSA4096 = "rsa-4096",
  HMAC = "hmac"
}

export enum HashAlgorithm {
  SHA256 = "sha256",
  SHA384 = "sha384",
  SHA512 = "sha512"
}

export enum MarshalingType {
  ASN1 = "asn1",
  JWS = "jws"
}

export interface TransitKeyVersion {
  version: number;
  key: Buffer;
  publicKey?: Buffer;
  privateKey?: Buffer;
  creationTime: Date;
  hmacKey?: Buffer;
}

export interface TransitKeyPolicy {
  name: string;
  type: TransitKeyType;
  derived: boolean;
  convergentEncryption: boolean;
  exportable: boolean;
  allowPlaintextBackup: boolean;
  minDecryptionVersion: number;
  minEncryptionVersion: number;
  latestVersion: number;
  autoRotatePeriod: number; // seconds, 0 = disabled
  deletionAllowed: boolean;
  keys: Map<number, TransitKeyVersion>;
  createdAt: Date;
  updatedAt: Date;
}

export interface TransitEncryptRequest {
  keyName: string;
  plaintext: string; // base64-encoded
  context?: string;  // base64-encoded derivation context
  keyVersion?: number;
  nonce?: string;    // base64, for convergent encryption
  associatedData?: string; // base64, AAD for AEAD
}

export interface TransitEncryptResponse {
  ciphertext: string; // "hanzo:v{N}:{base64}"
  keyVersion: number;
}

export interface TransitDecryptRequest {
  keyName: string;
  ciphertext: string;
  context?: string;
  nonce?: string;
  associatedData?: string;
}

export interface TransitDecryptResponse {
  plaintext: string; // base64
}

export interface TransitRewrapRequest {
  keyName: string;
  ciphertext: string;
  context?: string;
  nonce?: string;
  keyVersion?: number;
  associatedData?: string;
}

export interface TransitSignRequest {
  keyName: string;
  input: string; // base64
  keyVersion?: number;
  hashAlgorithm?: HashAlgorithm;
  context?: string;
  prehashed?: boolean;
  marshaling?: MarshalingType;
}

export interface TransitSignResponse {
  signature: string; // "hanzo:v{N}:{base64}"
  publicKey?: string;
}

export interface TransitVerifyRequest {
  keyName: string;
  input: string;
  signature: string;
  hashAlgorithm?: HashAlgorithm;
  context?: string;
  prehashed?: boolean;
  marshaling?: MarshalingType;
}

export interface TransitHmacRequest {
  keyName: string;
  input: string;
  keyVersion?: number;
  algorithm?: HashAlgorithm;
}

export interface TransitDataKeyRequest {
  keyName: string;
  context?: string;
  bits?: 128 | 256 | 512;
  nonce?: string;
}

export interface TransitDataKeyResponse {
  ciphertext: string;
  plaintext?: string; // only for "plaintext" variant
  keyVersion: number;
}

export interface BatchItem<T> {
  reference?: string;
  error?: string;
  data: T;
}

export interface TransitKeyInfo {
  name: string;
  type: TransitKeyType;
  derived: boolean;
  convergentEncryption: boolean;
  exportable: boolean;
  allowPlaintextBackup: boolean;
  deletionAllowed: boolean;
  minDecryptionVersion: number;
  minEncryptionVersion: number;
  latestVersion: number;
  autoRotatePeriod: number;
  supportsEncryption: boolean;
  supportsSigning: boolean;
  supportsDerivation: boolean;
  keys: Record<number, { creationTime: string; publicKey?: string }>;
}

export function supportsEncryption(type: TransitKeyType): boolean {
  return [
    TransitKeyType.AES256GCM96,
    TransitKeyType.AES128GCM96,
    TransitKeyType.ChaCha20Poly1305,
    TransitKeyType.RSA2048,
    TransitKeyType.RSA3072,
    TransitKeyType.RSA4096
  ].includes(type);
}

export function supportsSigning(type: TransitKeyType): boolean {
  return [
    TransitKeyType.Ed25519,
    TransitKeyType.ECDSA_P256,
    TransitKeyType.ECDSA_P384,
    TransitKeyType.RSA2048,
    TransitKeyType.RSA3072,
    TransitKeyType.RSA4096
  ].includes(type);
}

export function supportsDerivation(type: TransitKeyType): boolean {
  return [
    TransitKeyType.AES256GCM96,
    TransitKeyType.AES128GCM96,
    TransitKeyType.ChaCha20Poly1305,
    TransitKeyType.Ed25519
  ].includes(type);
}

export function isSymmetric(type: TransitKeyType): boolean {
  return [
    TransitKeyType.AES256GCM96,
    TransitKeyType.AES128GCM96,
    TransitKeyType.ChaCha20Poly1305,
    TransitKeyType.HMAC
  ].includes(type);
}
