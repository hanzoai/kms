// MPC Signing Requests schema
import { z } from "zod";

import { TImmutableDBKeys } from "./models";

export const MpcSigningStatusEnum = z.enum(["pending", "collecting", "signing", "completed", "failed", "cancelled"]);
export type TMpcSigningStatus = z.infer<typeof MpcSigningStatusEnum>;

export const MpcChainEnum = z.enum(["ethereum", "bitcoin", "solana", "lux", "xrpl", "polygon", "arbitrum", "optimism", "base", "avalanche"]);
export type TMpcChain = z.infer<typeof MpcChainEnum>;

export const MpcSigningRequestsSchema = z.object({
  id: z.string().uuid(),
  walletId: z.string().uuid(),
  initiatorUserId: z.string().uuid().nullable().optional(),
  chain: z.string(),
  txHash: z.string().nullable().optional(),
  rawTransaction: z.string().nullable().optional(),
  transactionDetails: z.record(z.unknown()).default({}),
  status: MpcSigningStatusEnum.default("pending"),
  signatures: z.array(z.unknown()).default([]),
  finalSignature: z.string().nullable().optional(),
  broadcastTxHash: z.string().nullable().optional(),
  errorMessage: z.string().nullable().optional(),
  requiredApprovals: z.number().int().min(1).default(2),
  expiresAt: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type TMpcSigningRequests = z.infer<typeof MpcSigningRequestsSchema>;
export type TMpcSigningRequestsInsert = Omit<z.input<typeof MpcSigningRequestsSchema>, TImmutableDBKeys>;
export type TMpcSigningRequestsUpdate = Partial<Omit<z.input<typeof MpcSigningRequestsSchema>, TImmutableDBKeys>>;
