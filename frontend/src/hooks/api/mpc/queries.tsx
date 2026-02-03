import { useQuery, UseQueryOptions } from "@tanstack/react-query";

import { apiRequest } from "@app/config/request";

import { OrderByDirection } from "../generic/types";
import {
  MpcNodeOrderBy,
  MpcNodeStatus,
  MpcSigningOrderBy,
  MpcSigningStatus,
  MpcWalletOrderBy,
  MpcWalletStatus,
  TListMpcNodesDTO,
  TListMpcWalletsDTO,
  TListSigningRequestsDTO,
  TListWalletTokensDTO,
  TMpcNodeList,
  TMpcSigningRequestList,
  TMpcStats,
  TMpcWalletList,
  TMpcWalletTokenList
} from "./types";

export const mpcKeys = {
  // Nodes
  getNodesByOrgId: ({ orgId, ...filters }: TListMpcNodesDTO) =>
    [{ orgId }, "mpc-nodes", filters] as const,
  getNodeById: (orgId: string, nodeId: string) =>
    [{ orgId }, "mpc-node", nodeId] as const,

  // Wallets
  getWalletsByProjectId: ({ orgId, projectId, ...filters }: TListMpcWalletsDTO) =>
    [{ orgId, projectId }, "mpc-wallets", filters] as const,
  getWalletById: (orgId: string, projectId: string, walletId: string) =>
    [{ orgId, projectId }, "mpc-wallet", walletId] as const,

  // Signing Requests
  getSigningRequests: ({ orgId, projectId, ...filters }: TListSigningRequestsDTO) =>
    [{ orgId, projectId }, "mpc-signing-requests", filters] as const,
  getSigningRequestById: (orgId: string, projectId: string, requestId: string) =>
    [{ orgId, projectId }, "mpc-signing-request", requestId] as const,

  // Tokens
  getWalletTokens: ({ walletId, ...filters }: TListWalletTokensDTO) =>
    [{ walletId }, "mpc-wallet-tokens", filters] as const,

  // Stats
  getStats: (orgId: string, projectId: string) =>
    [{ orgId, projectId }, "mpc-stats"] as const
};

// Node Queries
export const useGetMpcNodesByOrgId = (
  {
    orgId,
    offset = 0,
    limit = 100,
    orderBy = MpcNodeOrderBy.Name,
    orderDirection = OrderByDirection.ASC,
    search = "",
    status
  }: TListMpcNodesDTO,
  options?: Omit<
    UseQueryOptions<
      TMpcNodeList,
      unknown,
      TMpcNodeList,
      ReturnType<typeof mpcKeys.getNodesByOrgId>
    >,
    "queryKey" | "queryFn"
  >
) => {
  return useQuery({
    queryKey: mpcKeys.getNodesByOrgId({
      orgId,
      offset,
      limit,
      orderBy,
      orderDirection,
      search,
      status
    }),
    queryFn: async () => {
      const { data } = await apiRequest.get<TMpcNodeList>("/api/v1/mpc/nodes", {
        params: { orgId, offset, limit, search, orderBy, orderDirection, status }
      });

      return data;
    },
    enabled: Boolean(orgId) && (options?.enabled ?? true),
    placeholderData: (previousData) => previousData,
    ...options
  });
};

export const useGetMpcNodeById = (
  orgId: string,
  nodeId: string,
  options?: Omit<
    UseQueryOptions<
      TMpcNodeList["nodes"][0],
      unknown,
      TMpcNodeList["nodes"][0],
      ReturnType<typeof mpcKeys.getNodeById>
    >,
    "queryKey" | "queryFn"
  >
) => {
  return useQuery({
    queryKey: mpcKeys.getNodeById(orgId, nodeId),
    queryFn: async () => {
      const { data } = await apiRequest.get<TMpcNodeList["nodes"][0]>(
        `/api/v1/mpc/nodes/${nodeId}`
      );

      return data;
    },
    enabled: Boolean(orgId) && Boolean(nodeId) && (options?.enabled ?? true),
    ...options
  });
};

// Wallet Queries
export const useGetMpcWalletsByProjectId = (
  {
    orgId,
    projectId,
    offset = 0,
    limit = 100,
    orderBy = MpcWalletOrderBy.Name,
    orderDirection = OrderByDirection.ASC,
    search = "",
    status
  }: TListMpcWalletsDTO,
  options?: Omit<
    UseQueryOptions<
      TMpcWalletList,
      unknown,
      TMpcWalletList,
      ReturnType<typeof mpcKeys.getWalletsByProjectId>
    >,
    "queryKey" | "queryFn"
  >
) => {
  return useQuery({
    queryKey: mpcKeys.getWalletsByProjectId({
      orgId,
      projectId,
      offset,
      limit,
      orderBy,
      orderDirection,
      search,
      status
    }),
    queryFn: async () => {
      const { data } = await apiRequest.get<TMpcWalletList>("/api/v1/mpc/wallets", {
        params: { projectId, offset, limit, search, orderBy, orderDirection, status }
      });

      return data;
    },
    enabled: Boolean(projectId) && (options?.enabled ?? true),
    placeholderData: (previousData) => previousData,
    ...options
  });
};

export const useGetMpcWalletById = (
  orgId: string,
  projectId: string,
  walletId: string,
  options?: Omit<
    UseQueryOptions<
      TMpcWalletList["wallets"][0],
      unknown,
      TMpcWalletList["wallets"][0],
      ReturnType<typeof mpcKeys.getWalletById>
    >,
    "queryKey" | "queryFn"
  >
) => {
  return useQuery({
    queryKey: mpcKeys.getWalletById(orgId, projectId, walletId),
    queryFn: async () => {
      const { data } = await apiRequest.get<TMpcWalletList["wallets"][0]>(
        `/api/v1/mpc/wallets/${walletId}`
      );

      return data;
    },
    enabled: Boolean(projectId) && Boolean(walletId) && (options?.enabled ?? true),
    ...options
  });
};

// Signing Request Queries
export const useGetSigningRequests = (
  {
    orgId,
    projectId,
    offset = 0,
    limit = 100,
    orderBy = MpcSigningOrderBy.CreatedAt,
    orderDirection = OrderByDirection.DESC,
    status,
    walletId
  }: TListSigningRequestsDTO,
  options?: Omit<
    UseQueryOptions<
      TMpcSigningRequestList,
      unknown,
      TMpcSigningRequestList,
      ReturnType<typeof mpcKeys.getSigningRequests>
    >,
    "queryKey" | "queryFn"
  >
) => {
  return useQuery({
    queryKey: mpcKeys.getSigningRequests({
      orgId,
      projectId,
      offset,
      limit,
      orderBy,
      orderDirection,
      status,
      walletId
    }),
    queryFn: async () => {
      const { data } = await apiRequest.get<TMpcSigningRequestList>(
        "/api/v1/mpc/signing-requests",
        {
          params: { projectId, offset, limit, orderBy, orderDirection, status, walletId }
        }
      );

      return data;
    },
    enabled: Boolean(projectId) && (options?.enabled ?? true),
    placeholderData: (previousData) => previousData,
    ...options
  });
};

export const useGetSigningRequestById = (
  orgId: string,
  projectId: string,
  requestId: string,
  options?: Omit<
    UseQueryOptions<
      TMpcSigningRequestList["requests"][0],
      unknown,
      TMpcSigningRequestList["requests"][0],
      ReturnType<typeof mpcKeys.getSigningRequestById>
    >,
    "queryKey" | "queryFn"
  >
) => {
  return useQuery({
    queryKey: mpcKeys.getSigningRequestById(orgId, projectId, requestId),
    queryFn: async () => {
      const { data } = await apiRequest.get<TMpcSigningRequestList["requests"][0]>(
        `/api/v1/mpc/signing-requests/${requestId}`
      );

      return data;
    },
    enabled: Boolean(projectId) && Boolean(requestId) && (options?.enabled ?? true),
    ...options
  });
};

// Token Queries
export const useGetWalletTokens = (
  { walletId, chain }: TListWalletTokensDTO,
  options?: Omit<
    UseQueryOptions<
      TMpcWalletTokenList,
      unknown,
      TMpcWalletTokenList,
      ReturnType<typeof mpcKeys.getWalletTokens>
    >,
    "queryKey" | "queryFn"
  >
) => {
  return useQuery({
    queryKey: mpcKeys.getWalletTokens({ walletId, chain }),
    queryFn: async () => {
      const { data } = await apiRequest.get<TMpcWalletTokenList>(
        `/api/v1/mpc/wallets/${walletId}/tokens`,
        {
          params: { chain }
        }
      );

      return data;
    },
    enabled: Boolean(walletId) && (options?.enabled ?? true),
    ...options
  });
};

// Stats Query
export const useGetMpcStats = (
  orgId: string,
  projectId: string,
  options?: Omit<
    UseQueryOptions<
      TMpcStats,
      unknown,
      TMpcStats,
      ReturnType<typeof mpcKeys.getStats>
    >,
    "queryKey" | "queryFn"
  >
) => {
  return useQuery({
    queryKey: mpcKeys.getStats(orgId, projectId),
    queryFn: async () => {
      const { data } = await apiRequest.get<TMpcStats>("/api/v1/mpc/stats", {
        params: { projectId }
      });

      return data;
    },
    enabled: Boolean(projectId) && (options?.enabled ?? true),
    ...options
  });
};
