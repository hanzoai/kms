import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiRequest } from "@app/config/request";

import { mpcKeys } from "./queries";
import {
  TApproveSigningRequest,
  TCreateMpcNode,
  TCreateMpcWallet,
  TCreateSigningRequest,
  TDeleteMpcNode,
  TDeleteMpcWallet,
  TMpcNode,
  TMpcSigningRequest,
  TMpcWallet,
  TRejectSigningRequest,
  TUpdateMpcNode,
  TUpdateMpcWallet
} from "./types";

// Node Mutations
export const useCreateMpcNode = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (payload: TCreateMpcNode) => {
      const { data } = await apiRequest.post<TMpcNode>("/api/v1/mpc/nodes", payload);

      return data;
    },
    onSuccess: (_, { orgId }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getNodesByOrgId({ orgId })
      });
    }
  });
};

export const useUpdateMpcNode = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, orgId, ...payload }: TUpdateMpcNode) => {
      const { data } = await apiRequest.patch<TMpcNode>(`/api/v1/mpc/nodes/${id}`, payload);

      return data;
    },
    onSuccess: (_, { orgId, id }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getNodesByOrgId({ orgId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getNodeById(orgId, id)
      });
    }
  });
};

export const useDeleteMpcNode = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id }: TDeleteMpcNode) => {
      const { data } = await apiRequest.delete(`/api/v1/mpc/nodes/${id}`);

      return data;
    },
    onSuccess: (_, { orgId }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getNodesByOrgId({ orgId })
      });
    }
  });
};

export const useCheckMpcNodeHealth = () => {
  return useMutation({
    mutationFn: async (nodeId: string) => {
      const { data } = await apiRequest.post<{ status: string; latency: number }>(
        `/api/v1/mpc/nodes/${nodeId}/health`
      );

      return data;
    }
  });
};

// Wallet Mutations
export const useCreateMpcWallet = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (payload: TCreateMpcWallet) => {
      const { data } = await apiRequest.post<TMpcWallet>("/api/v1/mpc/wallets", payload);

      return data;
    },
    onSuccess: (_, { orgId, projectId }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getWalletsByProjectId({ orgId, projectId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getStats(orgId, projectId)
      });
    }
  });
};

export const useUpdateMpcWallet = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, orgId, projectId, ...payload }: TUpdateMpcWallet) => {
      const { data } = await apiRequest.patch<TMpcWallet>(`/api/v1/mpc/wallets/${id}`, payload);

      return data;
    },
    onSuccess: (_, { orgId, projectId, id }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getWalletsByProjectId({ orgId, projectId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getWalletById(orgId, projectId, id)
      });
    }
  });
};

export const useDeleteMpcWallet = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id }: TDeleteMpcWallet) => {
      const { data } = await apiRequest.delete(`/api/v1/mpc/wallets/${id}`);

      return data;
    },
    onSuccess: (_, { orgId, projectId }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getWalletsByProjectId({ orgId, projectId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getStats(orgId, projectId)
      });
    }
  });
};

// Signing Request Mutations
export const useCreateSigningRequest = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (payload: TCreateSigningRequest) => {
      const { data } = await apiRequest.post<TMpcSigningRequest>(
        "/api/v1/mpc/signing-requests",
        payload
      );

      return data;
    },
    onSuccess: (_, { orgId, projectId }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getSigningRequests({ orgId, projectId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getStats(orgId, projectId)
      });
    }
  });
};

export const useApproveSigningRequest = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id }: TApproveSigningRequest) => {
      const { data } = await apiRequest.post<TMpcSigningRequest>(
        `/api/v1/mpc/signing-requests/${id}/approve`
      );

      return data;
    },
    onSuccess: (_, { orgId, projectId, id }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getSigningRequests({ orgId, projectId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getSigningRequestById(orgId, projectId, id)
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getStats(orgId, projectId)
      });
    }
  });
};

export const useRejectSigningRequest = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, reason }: TRejectSigningRequest) => {
      const { data } = await apiRequest.post<TMpcSigningRequest>(
        `/api/v1/mpc/signing-requests/${id}/reject`,
        { reason }
      );

      return data;
    },
    onSuccess: (_, { orgId, projectId, id }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getSigningRequests({ orgId, projectId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getSigningRequestById(orgId, projectId, id)
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getStats(orgId, projectId)
      });
    }
  });
};

export const useCancelSigningRequest = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id }: { id: string; orgId: string; projectId: string }) => {
      const { data } = await apiRequest.post<TMpcSigningRequest>(
        `/api/v1/mpc/signing-requests/${id}/cancel`
      );

      return data;
    },
    onSuccess: (_, { orgId, projectId }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getSigningRequests({ orgId, projectId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getStats(orgId, projectId)
      });
    }
  });
};

// Transfer Mutations
export const useInitiateTransfer = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (payload: {
      walletId: string;
      chain: string;
      to: string;
      amount: string;
      tokenAddress?: string;
      orgId: string;
      projectId: string;
    }) => {
      const { data } = await apiRequest.post<TMpcSigningRequest>(
        "/api/v1/mpc/transfers",
        payload
      );

      return data;
    },
    onSuccess: (_, { orgId, projectId }) => {
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getSigningRequests({ orgId, projectId })
      });
      queryClient.invalidateQueries({
        queryKey: mpcKeys.getStats(orgId, projectId)
      });
    }
  });
};
