import { Knex } from "knex";

// Supported blockchain chains
export enum MpcChain {
  Ethereum = "ethereum",
  Bitcoin = "bitcoin",
  Solana = "solana",
  Lux = "lux",
  XRPL = "xrpl",
  Polygon = "polygon",
  Arbitrum = "arbitrum",
  Optimism = "optimism",
  Base = "base",
  Avalanche = "avalanche",
  BNBChain = "bnb"
}

// Key types supported by MPC
export enum MpcKeyType {
  ECDSA = "ecdsa",
  EdDSA = "eddsa",
  Taproot = "taproot"
}

// Node DTOs
export type TCreateMpcNodeDTO = {
  orgId: string;
  name: string;
  nodeId: string;
  publicKey?: string;
  endpoint?: string;
  port?: number;
  metadata?: Record<string, unknown>;
};

export type TUpdateMpcNodeDTO = {
  id: string;
  orgId: string;
  name?: string;
  publicKey?: string;
  endpoint?: string;
  port?: number;
  metadata?: Record<string, unknown>;
};

export type TDeleteMpcNodeDTO = {
  id: string;
  orgId: string;
};

export type TListMpcNodesDTO = {
  orgId: string;
};

export type TGetMpcNodeDTO = {
  id: string;
  orgId: string;
};

// Wallet DTOs
export type TCreateMpcWalletDTO = {
  orgId: string;
  projectId?: string;
  name: string;
  keyType?: MpcKeyType;
  threshold?: number;
  totalParties?: number;
  participantNodeIds?: string[];
};

export type TUpdateMpcWalletDTO = {
  id: string;
  orgId: string;
  name?: string;
  projectId?: string;
};

export type TDeleteMpcWalletDTO = {
  id: string;
  orgId: string;
};

export type TListMpcWalletsDTO = {
  orgId: string;
  projectId?: string;
};

export type TGetMpcWalletDTO = {
  id: string;
  orgId: string;
};

// Signing Request DTOs
export type TCreateSigningRequestDTO = {
  walletId: string;
  chain: MpcChain | string;
  initiatorUserId?: string;
  rawTransaction: string;
  transactionDetails?: Record<string, unknown>;
  requiredApprovals?: number;
  expiresInMinutes?: number;
};

export type TApproveSigningRequestDTO = {
  signingRequestId: string;
  userId?: string;
  nodeId?: string;
  signatureShare?: string;
  comment?: string;
};

export type TRejectSigningRequestDTO = {
  signingRequestId: string;
  userId?: string;
  nodeId?: string;
  comment?: string;
};

export type TGetSigningRequestDTO = {
  id: string;
  orgId: string;
};

export type TListSigningRequestsDTO = {
  walletId?: string;
  orgId: string;
  status?: string;
};

// Token DTOs
export type TListWalletTokensDTO = {
  walletId: string;
  chain?: string;
};

export type TUpdateTokenBalanceDTO = {
  walletId: string;
  chain: string;
  tokenAddress?: string;
  symbol: string;
  name?: string;
  decimals?: number;
  balance: string;
  balanceUsd?: string;
};

// Transaction History DTOs
export type TListTransactionHistoryDTO = {
  walletId: string;
  chain?: string;
  type?: string;
  limit?: number;
  offset?: number;
};

export type TAddTransactionDTO = {
  walletId: string;
  signingRequestId?: string;
  chain: string;
  txHash: string;
  type: "send" | "receive" | "contract" | "approve" | "swap";
  fromAddress?: string;
  toAddress?: string;
  amount?: string;
  tokenAddress?: string;
  tokenSymbol?: string;
  fee?: string;
};

// MPC Cluster Communication Types
export type TMpcNodeHealth = {
  nodeId: string;
  status: "online" | "offline" | "syncing" | "error";
  version: string;
  uptime: number;
  lastBlock?: number;
  peerCount?: number;
};

export type TMpcKeygenRequest = {
  walletId: string;
  keyType: MpcKeyType;
  threshold: number;
  participantNodeIds: string[];
};

export type TMpcKeygenResult = {
  walletId: string;
  publicKey: string;
  chainAddresses: Record<string, string>;
  participantNodeIds: string[];
};

export type TMpcSignRequest = {
  walletId: string;
  chain: string;
  txHash: string;
  rawTransaction: string;
  participantNodeIds: string[];
};

export type TMpcSignResult = {
  signature: string;
  recoveryId?: number;
  r?: string;
  s?: string;
  v?: number;
};
