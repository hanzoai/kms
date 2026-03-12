export enum SealType {
  Shamir = "shamir",
  AwsKms = "awskms",
  GcpKms = "gcpkms"
}

export interface SealConfig {
  type: SealType;
  secretShares: number;
  secretThreshold: number;
}

export interface SealStatus {
  sealed: boolean;
  type: SealType;
  totalShares: number;
  threshold: number;
  unsealProgress: number;
  unsealKeysProvided: number;
  initialized: boolean;
  version: number;
}

export interface KmsWrapper {
  encrypt(plaintext: Buffer): Promise<Buffer>;
  decrypt(ciphertext: Buffer): Promise<Buffer>;
  isHealthy(): Promise<boolean>;
}

export interface BarrierKeyring {
  activeTerm: number;
  keys: Map<number, Buffer>;
}
