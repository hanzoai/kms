// MPC Signing Approvals schema
import { z } from "zod";

import { TImmutableDBKeys } from "./models";

export const MpcApprovalTypeEnum = z.enum(["user", "node"]);
export type TMpcApprovalType = z.infer<typeof MpcApprovalTypeEnum>;

export const MpcApprovalStatusEnum = z.enum(["pending", "approved", "rejected"]);
export type TMpcApprovalStatus = z.infer<typeof MpcApprovalStatusEnum>;

export const MpcSigningApprovalsSchema = z.object({
  id: z.string().uuid(),
  signingRequestId: z.string().uuid(),
  userId: z.string().uuid().nullable().optional(),
  nodeId: z.string().uuid().nullable().optional(),
  approvalType: MpcApprovalTypeEnum,
  status: MpcApprovalStatusEnum.default("pending"),
  signatureShare: z.string().nullable().optional(),
  comment: z.string().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type TMpcSigningApprovals = z.infer<typeof MpcSigningApprovalsSchema>;
export type TMpcSigningApprovalsInsert = Omit<z.input<typeof MpcSigningApprovalsSchema>, TImmutableDBKeys>;
export type TMpcSigningApprovalsUpdate = Partial<Omit<z.input<typeof MpcSigningApprovalsSchema>, TImmutableDBKeys>>;
