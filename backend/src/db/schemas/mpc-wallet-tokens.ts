// MPC Wallet Tokens schema
import { z } from "zod";

import { TImmutableDBKeys } from "./models";

export const MpcWalletTokensSchema = z.object({
  id: z.string().uuid(),
  walletId: z.string().uuid(),
  chain: z.string(),
  tokenAddress: z.string().nullable().optional(), // null for native tokens
  symbol: z.string(),
  name: z.string().nullable().optional(),
  decimals: z.number().int().default(18),
  balance: z.string().default("0"),
  balanceUsd: z.string().nullable().optional(),
  lastUpdated: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type TMpcWalletTokens = z.infer<typeof MpcWalletTokensSchema>;
export type TMpcWalletTokensInsert = Omit<z.input<typeof MpcWalletTokensSchema>, TImmutableDBKeys>;
export type TMpcWalletTokensUpdate = Partial<Omit<z.input<typeof MpcWalletTokensSchema>, TImmutableDBKeys>>;
