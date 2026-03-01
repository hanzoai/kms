import { z } from "zod";

import { TImmutableDBKeys } from "./models";

export const AiReadRequestStatus = {
  Pending: "pending",
  Approved: "approved",
  Denied: "denied",
  Expired: "expired"
} as const;

export const AiSecretReadRequestsSchema = z.object({
  id: z.string().uuid(),
  policyId: z.string().uuid(),
  identityId: z.string().uuid(),
  secretKey: z.string(),
  secretPath: z.string(),
  environment: z.string(),
  projectId: z.string(),
  agentType: z.string().nullable().optional(),
  tool: z.string().nullable().optional(),
  deviceId: z.string().nullable().optional(),
  reason: z.string().nullable().optional(),
  status: z.enum(["pending", "approved", "denied", "expired"]).default("pending"),
  reviewedBy: z.string().nullable().optional(),
  expiresAt: z.date(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type TAiSecretReadRequests = z.infer<typeof AiSecretReadRequestsSchema>;
export type TAiSecretReadRequestsInsert = Omit<z.input<typeof AiSecretReadRequestsSchema>, TImmutableDBKeys>;
export type TAiSecretReadRequestsUpdate = Partial<Omit<z.input<typeof AiSecretReadRequestsSchema>, TImmutableDBKeys>>;
