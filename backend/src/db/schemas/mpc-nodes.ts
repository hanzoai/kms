// MPC Nodes schema
import { z } from "zod";

import { TImmutableDBKeys } from "./models";

export const MpcNodeStatusEnum = z.enum(["online", "offline", "syncing", "error"]);
export type TMpcNodeStatus = z.infer<typeof MpcNodeStatusEnum>;

export const MpcNodesSchema = z.object({
  id: z.string().uuid(),
  orgId: z.string().uuid(),
  name: z.string(),
  nodeId: z.string(),
  publicKey: z.string().nullable().optional(),
  endpoint: z.string().nullable().optional(),
  port: z.number().default(8080),
  status: MpcNodeStatusEnum.default("offline"),
  metadata: z.record(z.unknown()).default({}),
  lastSeen: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type TMpcNodes = z.infer<typeof MpcNodesSchema>;
export type TMpcNodesInsert = Omit<z.input<typeof MpcNodesSchema>, TImmutableDBKeys>;
export type TMpcNodesUpdate = Partial<Omit<z.input<typeof MpcNodesSchema>, TImmutableDBKeys>>;
