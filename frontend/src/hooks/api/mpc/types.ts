import { OrderByDirection } from "../generic/types";

// Enums
export enum MpcNodeStatus {
  Online = "online",
  Offline = "offline",
  Syncing = "syncing",
  Error = "error"
}

export enum MpcWalletStatus {
  Active = "active",
  Pending = "pending",
  Rotating = "rotating",
  Archived = "archived"
}

export enum MpcKeyType {
  ECDSA = "ecdsa",
  EdDSA = "eddsa"
}

export enum MpcChain {
  Ethereum = "ethereum",
  Bitcoin = "bitcoin",
  Solana = "solana",
  Lux = "lux",
  XRPL = "xrpl"
}

export enum MpcSigningStatus {
  Pending = "pending",
  Collecting = "collecting",
  Signing = "signing",
  Completed = "completed",
  Failed = "failed",
  Cancelled = "cancelled"
}

export enum MpcNodeOrderBy {
  Name = "name",
  Status = "status",
  CreatedAt = "createdAt"
}

export enum MpcWalletOrderBy {
  Name = "name",
  Status = "status",
  CreatedAt = "createdAt"
}

export enum MpcSigningOrderBy {
  CreatedAt = "createdAt",
  Status = "status"
}

// Node Types
export type TMpcNode = {
  id: string;
  orgId: string;
  name: string;
  nodeId: string;
  endpoint: string;
  port: number;
  status: MpcNodeStatus;
  lastSeen?: string;
  metadata?: {
    version?: string;
    uptime?: number;
  };
  createdAt: string;
  updatedAt: string;
};

export type TCreateMpcNode = {
  orgId: string;
  name: string;
  endpoint: string;
  port: number;
  authToken?: string;
};

export type TUpdateMpcNode = {
  id: string;
  orgId: string;
  name?: string;
  endpoint?: string;
  port?: number;
  authToken?: string;
};

export type TDeleteMpcNode = {
  id: string;
  orgId: string;
};

export type TListMpcNodesDTO = {
  orgId: string;
  offset?: number;
  limit?: number;
  orderBy?: MpcNodeOrderBy;
  orderDirection?: OrderByDirection;
  search?: string;
  status?: MpcNodeStatus;
};

export type TMpcNodeList = {
  nodes: TMpcNode[];
  totalCount: number;
};

// Wallet Types
export type TMpcWallet = {
  id: string;
  orgId: string;
  projectId: string;
  name: string;
  walletId: string;
  keyType: MpcKeyType;
  threshold: number;
  totalParties: number;
  status: MpcWalletStatus;
  publicKey?: string;
  chainAddresses?: Record<string, string>;
  createdAt: string;
  updatedAt: string;
};

export type TCreateMpcWallet = {
  orgId: string;
  projectId: string;
  name: string;
  keyType: MpcKeyType;
  threshold: number;
  totalParties: number;
  chains: MpcChain[];
};

export type TUpdateMpcWallet = {
  id: string;
  orgId: string;
  projectId: string;
  name?: string;
  status?: MpcWalletStatus;
};

export type TDeleteMpcWallet = {
  id: string;
  orgId: string;
  projectId: string;
};

export type TListMpcWalletsDTO = {
  orgId: string;
  projectId: string;
  offset?: number;
  limit?: number;
  orderBy?: MpcWalletOrderBy;
  orderDirection?: OrderByDirection;
  search?: string;
  status?: MpcWalletStatus;
};

export type TMpcWalletList = {
  wallets: TMpcWallet[];
  totalCount: number;
};

// Signing Request Types
export type TTransactionDetails = {
  to: string;
  value?: string;
  data?: string;
  type?: string;
};

export type TMpcSigningRequest = {
  id: string;
  orgId: string;
  projectId: string;
  walletId: string;
  walletName?: string;
  chain: MpcChain;
  status: MpcSigningStatus;
  requiredApprovals: number;
  currentApprovals: number;
  transactionDetails: TTransactionDetails;
  initiator: string;
  broadcastTxHash?: string;
  createdAt: string;
  expiresAt?: string;
};

export type TCreateSigningRequest = {
  orgId: string;
  projectId: string;
  walletId: string;
  chain: MpcChain;
  transactionDetails: TTransactionDetails;
};

export type TApproveSigningRequest = {
  id: string;
  orgId: string;
  projectId: string;
};

export type TRejectSigningRequest = {
  id: string;
  orgId: string;
  projectId: string;
  reason?: string;
};

export type TListSigningRequestsDTO = {
  orgId: string;
  projectId: string;
  offset?: number;
  limit?: number;
  orderBy?: MpcSigningOrderBy;
  orderDirection?: OrderByDirection;
  status?: MpcSigningStatus;
  walletId?: string;
};

export type TMpcSigningRequestList = {
  requests: TMpcSigningRequest[];
  totalCount: number;
};

// Token Types
export type TMpcWalletToken = {
  id: string;
  walletId: string;
  chain: MpcChain;
  contractAddress?: string;
  symbol: string;
  name: string;
  decimals: number;
  balance: string;
  updatedAt: string;
};

export type TListWalletTokensDTO = {
  walletId: string;
  chain?: MpcChain;
};

export type TMpcWalletTokenList = {
  tokens: TMpcWalletToken[];
};

// Stats Types
export type TMpcStats = {
  totalNodes: number;
  onlineNodes: number;
  totalWallets: number;
  activeWallets: number;
  pendingSignatures: number;
  transactions24h: number;
};
