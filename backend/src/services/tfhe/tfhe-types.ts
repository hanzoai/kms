/**
 * TFHE (Threshold Fully Homomorphic Encryption) integration types.
 *
 * Bridges Hanzo KMS with the MPC TFHE subsystem (luxfi/fhe)
 * and the T-Chain on-chain FHE precompile.
 *
 * Architecture:
 *   KMS (key storage, policy, audit) → MPC (TFHE keygen/compute) → T-Chain (on-chain FHE)
 */

export enum FheKeyType {
  TFHE_UINT8 = "tfhe-uint8",
  TFHE_UINT16 = "tfhe-uint16",
  TFHE_UINT32 = "tfhe-uint32",
  TFHE_UINT64 = "tfhe-uint64",
  TFHE_UINT128 = "tfhe-uint128",
  TFHE_UINT256 = "tfhe-uint256",
  TFHE_BOOL = "tfhe-bool",
  TFHE_ADDRESS = "tfhe-address"
}

export interface TfheKeyConfig {
  id: string;
  name: string;
  walletId: string;             // MPC wallet ID for threshold keygen
  keyType: FheKeyType;
  threshold: number;            // t-of-n threshold
  totalParties: number;
  generation: number;           // key generation version
  publicKeyRef: string;         // storage reference for FHE public key
  status: "pending" | "active" | "rotating" | "revoked";
  createdAt: Date;
  updatedAt: Date;
}

export interface EncryptedValue {
  ciphertext: Buffer;
  keyId: string;
  keyType: FheKeyType;
  generation: number;
}

export interface DecryptionShareRequest {
  keyId: string;
  ciphertext: Buffer;
  partyId: number;
}

export interface DecryptionShare {
  partyId: number;
  share: Buffer;
  keyId: string;
}

export interface TfheComputeRequest {
  operation: TfheOperation;
  keyId: string;
  operands: EncryptedValue[];
  plaintextOperand?: bigint;    // for mixed plaintext/ciphertext ops
}

export enum TfheOperation {
  // Arithmetic
  Add = "add",
  Sub = "sub",
  Mul = "mul",
  Div = "div",

  // Comparisons (return encrypted bool)
  Lt = "lt",
  Gt = "gt",
  Lte = "lte",
  Gte = "gte",
  Eq = "eq",
  Ne = "ne",

  // Boolean
  And = "and",
  Or = "or",
  Xor = "xor",
  Not = "not",

  // Branching
  Select = "select",    // if(control, ifTrue, ifFalse) on encrypted condition

  // Type conversion
  Cast = "cast",

  // Encryption
  TrivialEncrypt = "trivial_encrypt",

  // Threshold decryption
  SealOutput = "seal_output"
}

export interface PrivatePolicyRule {
  opcode: PrivatePolicyOpcode;
  encryptedThreshold?: EncryptedValue;
  encryptedWhitelist?: EncryptedValue[];
  timeWindowStart?: number;
  timeWindowEnd?: number;
}

export enum PrivatePolicyOpcode {
  // Private (TFHE) policy operations - evaluated on encrypted data
  PrivateAmountLT = 0x80,
  PrivateAmountGT = 0x81,
  PrivateCumulative = 0x82,
  PrivateWhitelist = 0x83,
  PrivateAmountRange = 0x84,
  PrivateTimeWindow = 0x85
}

export interface EncryptedPolicyState {
  cumulativeDaily: EncryptedValue;
  cumulativeMonthly: EncryptedValue;
  lastTxTime: EncryptedValue;
  vestedAmount?: EncryptedValue;
  streamedAmount?: EncryptedValue;
}

/**
 * T-Chain FHE precompile interface for on-chain operations.
 * Precompile address: 0x0700000000000000000000000000000000000080
 */
export interface TChainFheConfig {
  rpcUrl: string;
  precompileAddress: string;
  gatewayAddress: string;       // for threshold decryption callbacks
  chainId: number;
}
