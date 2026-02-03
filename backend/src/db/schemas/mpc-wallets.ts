// MPC Wallets schema
import { z } from "zod";

import { TImmutableDBKeys } from "./models";

export const MpcKeyTypeEnum = z.enum(["ecdsa", "eddsa", "taproot"]);
export type TMpcKeyType = z.infer<typeof MpcKeyTypeEnum>;

export const MpcWalletStatusEnum = z.enum(["pending", "active", "rotating", "archived"]);
export type TMpcWalletStatus = z.infer<typeof MpcWalletStatusEnum>;

export const MpcWalletsSchema = z.object({
  id: z.string().uuid(),
  orgId: z.string().uuid(),
  projectId: z.string().uuid().nullable().optional(),
  name: z.string(),
  walletId: z.string(),
  keyType: MpcKeyTypeEnum.default("ecdsa"),
  threshold: z.number().int().min(1).default(2),
  totalParties: z.number().int().min(2).default(3),
  participantNodeIds: z.array(z.string()).default([]),
  publicKey: z.string().nullable().optional(),
  status: MpcWalletStatusEnum.default("pending"),
  chainAddresses: z.record(z.string()).default({}),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type TMpcWallets = z.infer<typeof MpcWalletsSchema>;
export type TMpcWalletsInsert = Omit<z.input<typeof MpcWalletsSchema>, TImmutableDBKeys>;
export type TMpcWalletsUpdate = Partial<Omit<z.input<typeof MpcWalletsSchema>, TImmutableDBKeys>>;
