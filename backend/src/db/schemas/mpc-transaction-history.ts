// MPC Transaction History schema
import { z } from "zod";

import { TImmutableDBKeys } from "./models";

export const MpcTransactionTypeEnum = z.enum(["send", "receive", "contract", "approve", "swap"]);
export type TMpcTransactionType = z.infer<typeof MpcTransactionTypeEnum>;

export const MpcTransactionStatusEnum = z.enum(["pending", "confirmed", "failed"]);
export type TMpcTransactionStatus = z.infer<typeof MpcTransactionStatusEnum>;

export const MpcTransactionHistorySchema = z.object({
  id: z.string().uuid(),
  walletId: z.string().uuid(),
  signingRequestId: z.string().uuid().nullable().optional(),
  chain: z.string(),
  txHash: z.string(),
  type: MpcTransactionTypeEnum,
  fromAddress: z.string().nullable().optional(),
  toAddress: z.string().nullable().optional(),
  amount: z.string().nullable().optional(),
  tokenAddress: z.string().nullable().optional(), // null for native
  tokenSymbol: z.string().nullable().optional(),
  fee: z.string().nullable().optional(),
  status: MpcTransactionStatusEnum.default("pending"),
  confirmations: z.number().int().default(0),
  blockNumber: z.number().int().nullable().optional(),
  confirmedAt: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type TMpcTransactionHistory = z.infer<typeof MpcTransactionHistorySchema>;
export type TMpcTransactionHistoryInsert = Omit<z.input<typeof MpcTransactionHistorySchema>, TImmutableDBKeys>;
export type TMpcTransactionHistoryUpdate = Partial<Omit<z.input<typeof MpcTransactionHistorySchema>, TImmutableDBKeys>>;
