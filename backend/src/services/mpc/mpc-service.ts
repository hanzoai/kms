import crypto from "crypto";

import { ForbiddenRequestError, NotFoundError } from "@app/lib/errors";
import { logger } from "@app/lib/logger";

import { TMpcNodeDALFactory } from "./mpc-node-dal";
import {
  MpcKeyType,
  TApproveSigningRequestDTO,
  TCreateMpcNodeDTO,
  TCreateMpcWalletDTO,
  TCreateSigningRequestDTO,
  TDeleteMpcNodeDTO,
  TDeleteMpcWalletDTO,
  TGetMpcNodeDTO,
  TGetMpcWalletDTO,
  TGetSigningRequestDTO,
  TListMpcNodesDTO,
  TListMpcWalletsDTO,
  TListSigningRequestsDTO,
  TListTransactionHistoryDTO,
  TListWalletTokensDTO,
  TRejectSigningRequestDTO,
  TUpdateMpcNodeDTO,
  TUpdateMpcWalletDTO,
  TUpdateTokenBalanceDTO
} from "./mpc-types";
import { TMpcWalletDALFactory } from "./mpc-wallet-dal";

type TMpcServiceFactoryDep = {
  mpcNodeDAL: TMpcNodeDALFactory;
  mpcWalletDAL: TMpcWalletDALFactory;
  // mpcSigningRequestDAL: TMpcSigningRequestDALFactory;
  // mpcSigningApprovalDAL: TMpcSigningApprovalDALFactory;
  // mpcWalletTokenDAL: TMpcWalletTokenDALFactory;
  // mpcTransactionHistoryDAL: TMpcTransactionHistoryDALFactory;
};

export type TMpcServiceFactory = ReturnType<typeof mpcServiceFactory>;

export const mpcServiceFactory = ({
  mpcNodeDAL,
  mpcWalletDAL
}: TMpcServiceFactoryDep) => {
  // ============================================
  // Node Management
  // ============================================

  const createNode = async (dto: TCreateMpcNodeDTO) => {
    const { orgId, name, nodeId, publicKey, endpoint, port, metadata } = dto;

    // Check if node already exists
    const existingNode = await mpcNodeDAL.findByNodeId(orgId, nodeId);
    if (existingNode) {
      throw new ForbiddenRequestError({ message: "MPC node with this ID already exists" });
    }

    const node = await mpcNodeDAL.create({
      orgId,
      name,
      nodeId,
      publicKey,
      endpoint,
      port: port ?? 8080,
      metadata: metadata ?? {},
      status: "offline"
    });

    logger.info("MPC node created", { nodeId: node.id, orgId });
    return node;
  };

  const updateNode = async (dto: TUpdateMpcNodeDTO) => {
    const { id, orgId, ...updateData } = dto;

    const existingNode = await mpcNodeDAL.findById(id);
    if (!existingNode || existingNode.orgId !== orgId) {
      throw new NotFoundError({ message: "MPC node not found" });
    }

    const node = await mpcNodeDAL.updateById(id, updateData);
    logger.info("MPC node updated", { nodeId: id, orgId });
    return node;
  };

  const deleteNode = async (dto: TDeleteMpcNodeDTO) => {
    const { id, orgId } = dto;

    const existingNode = await mpcNodeDAL.findById(id);
    if (!existingNode || existingNode.orgId !== orgId) {
      throw new NotFoundError({ message: "MPC node not found" });
    }

    // Check if node is participating in any active wallets
    const activeWallets = await mpcWalletDAL.findActiveWallets(orgId);
    const participatingWallets = activeWallets.filter(
      (w) => w.participantNodeIds && w.participantNodeIds.includes(existingNode.nodeId)
    );

    if (participatingWallets.length > 0) {
      throw new ForbiddenRequestError({
        message: `Cannot delete node. It is participating in ${participatingWallets.length} active wallet(s)`
      });
    }

    await mpcNodeDAL.deleteById(id);
    logger.info("MPC node deleted", { nodeId: id, orgId });
    return { success: true };
  };

  const listNodes = async (dto: TListMpcNodesDTO) => {
    return mpcNodeDAL.findByOrgId(dto.orgId);
  };

  const getNode = async (dto: TGetMpcNodeDTO) => {
    const { id, orgId } = dto;
    const node = await mpcNodeDAL.findById(id);
    if (!node || node.orgId !== orgId) {
      throw new NotFoundError({ message: "MPC node not found" });
    }
    return node;
  };

  const updateNodeHealth = async (nodeId: string, status: "online" | "offline" | "syncing" | "error") => {
    // This would be called by the MPC node health check endpoint
    const node = await mpcNodeDAL.findById(nodeId);
    if (!node) {
      throw new NotFoundError({ message: "MPC node not found" });
    }
    return mpcNodeDAL.updateStatus(nodeId, status, new Date());
  };

  // ============================================
  // Wallet Management
  // ============================================

  const createWallet = async (dto: TCreateMpcWalletDTO) => {
    const {
      orgId,
      projectId,
      name,
      keyType = MpcKeyType.ECDSA,
      threshold = 2,
      totalParties = 3,
      participantNodeIds = []
    } = dto;

    // Validate threshold
    if (threshold < 1 || threshold >= totalParties) {
      throw new ForbiddenRequestError({
        message: `Invalid threshold: must be between 1 and ${totalParties - 1}`
      });
    }

    // Validate participant nodes exist and are online
    if (participantNodeIds.length > 0) {
      const onlineNodes = await mpcNodeDAL.findOnlineNodes(orgId);
      const onlineNodeIds = onlineNodes.map((n) => n.nodeId);
      const missingNodes = participantNodeIds.filter((id) => !onlineNodeIds.includes(id));

      if (missingNodes.length > 0) {
        throw new ForbiddenRequestError({
          message: `Some participant nodes are not available: ${missingNodes.join(", ")}`
        });
      }
    }

    // Generate unique wallet ID
    const walletId = `wallet_${crypto.randomBytes(16).toString("hex")}`;

    const wallet = await mpcWalletDAL.create({
      orgId,
      projectId,
      name,
      walletId,
      keyType,
      threshold,
      totalParties,
      participantNodeIds,
      status: "pending",
      chainAddresses: {}
    });

    logger.info("MPC wallet created", { walletId: wallet.id, orgId });

    // TODO: Trigger key generation across MPC nodes
    // This would involve:
    // 1. Notifying all participant nodes
    // 2. Running the DKG protocol (CGGMP21 or FROST depending on keyType)
    // 3. Collecting public key and deriving chain addresses
    // 4. Updating wallet status to "active"

    return wallet;
  };

  const updateWallet = async (dto: TUpdateMpcWalletDTO) => {
    const { id, orgId, ...updateData } = dto;

    const existingWallet = await mpcWalletDAL.findById(id);
    if (!existingWallet || existingWallet.orgId !== orgId) {
      throw new NotFoundError({ message: "MPC wallet not found" });
    }

    const wallet = await mpcWalletDAL.updateById(id, updateData);
    logger.info("MPC wallet updated", { walletId: id, orgId });
    return wallet;
  };

  const deleteWallet = async (dto: TDeleteMpcWalletDTO) => {
    const { id, orgId } = dto;

    const existingWallet = await mpcWalletDAL.findById(id);
    if (!existingWallet || existingWallet.orgId !== orgId) {
      throw new NotFoundError({ message: "MPC wallet not found" });
    }

    // Mark as archived instead of hard delete
    await mpcWalletDAL.updateStatus(id, "archived");
    logger.info("MPC wallet archived", { walletId: id, orgId });
    return { success: true };
  };

  const listWallets = async (dto: TListMpcWalletsDTO) => {
    if (dto.projectId) {
      return mpcWalletDAL.findByProjectId(dto.projectId);
    }
    return mpcWalletDAL.findByOrgId(dto.orgId);
  };

  const getWallet = async (dto: TGetMpcWalletDTO) => {
    const { id, orgId } = dto;
    const wallet = await mpcWalletDAL.findById(id);
    if (!wallet || wallet.orgId !== orgId) {
      throw new NotFoundError({ message: "MPC wallet not found" });
    }
    return wallet;
  };

  const getWalletAddresses = async (walletId: string, orgId: string) => {
    const wallet = await mpcWalletDAL.findById(walletId);
    if (!wallet || wallet.orgId !== orgId) {
      throw new NotFoundError({ message: "MPC wallet not found" });
    }
    return {
      walletId: wallet.walletId,
      publicKey: wallet.publicKey,
      addresses: wallet.chainAddresses
    };
  };

  // ============================================
  // Signing Requests (Placeholder implementations)
  // ============================================

  const createSigningRequest = async (dto: TCreateSigningRequestDTO) => {
    // TODO: Implement signing request creation
    // This would:
    // 1. Validate the wallet exists and is active
    // 2. Parse and validate the raw transaction
    // 3. Create the signing request record
    // 4. Notify required approvers
    logger.info("Signing request creation - not yet implemented", dto);
    throw new NotFoundError({ message: "Signing request creation not yet implemented" });
  };

  const approveSigningRequest = async (dto: TApproveSigningRequestDTO) => {
    // TODO: Implement signing approval
    logger.info("Signing approval - not yet implemented", dto);
    throw new NotFoundError({ message: "Signing approval not yet implemented" });
  };

  const rejectSigningRequest = async (dto: TRejectSigningRequestDTO) => {
    // TODO: Implement signing rejection
    logger.info("Signing rejection - not yet implemented", dto);
    throw new NotFoundError({ message: "Signing rejection not yet implemented" });
  };

  const getSigningRequest = async (dto: TGetSigningRequestDTO) => {
    // TODO: Implement get signing request
    throw new NotFoundError({ message: "Signing request not found" });
  };

  const listSigningRequests = async (dto: TListSigningRequestsDTO) => {
    // TODO: Implement list signing requests
    return [];
  };

  // ============================================
  // Token & Balance Management (Placeholder)
  // ============================================

  const listWalletTokens = async (dto: TListWalletTokensDTO) => {
    // TODO: Implement token listing
    return [];
  };

  const updateTokenBalance = async (dto: TUpdateTokenBalanceDTO) => {
    // TODO: Implement balance update
    logger.info("Token balance update - not yet implemented", dto);
    return null;
  };

  const refreshWalletBalances = async (walletId: string, orgId: string) => {
    // TODO: Fetch balances from blockchain nodes
    logger.info("Balance refresh - not yet implemented", { walletId, orgId });
    return [];
  };

  // ============================================
  // Transaction History (Placeholder)
  // ============================================

  const listTransactionHistory = async (dto: TListTransactionHistoryDTO) => {
    // TODO: Implement transaction history
    return [];
  };

  return {
    // Node management
    createNode,
    updateNode,
    deleteNode,
    listNodes,
    getNode,
    updateNodeHealth,

    // Wallet management
    createWallet,
    updateWallet,
    deleteWallet,
    listWallets,
    getWallet,
    getWalletAddresses,

    // Signing requests
    createSigningRequest,
    approveSigningRequest,
    rejectSigningRequest,
    getSigningRequest,
    listSigningRequests,

    // Tokens & balances
    listWalletTokens,
    updateTokenBalance,
    refreshWalletBalances,

    // Transaction history
    listTransactionHistory
  };
};
