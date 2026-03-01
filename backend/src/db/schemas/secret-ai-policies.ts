import { z } from "zod";

import { TImmutableDBKeys } from "./models";

export const AiSecretPolicy = {
  AutoApprove: "auto-approve",
  RequiresApproval: "requires-approval",
  Blocked: "blocked"
} as const;

export type TAiSecretPolicy = (typeof AiSecretPolicy)[keyof typeof AiSecretPolicy];

export const SecretAiPoliciesSchema = z.object({
  id: z.string().uuid(),
  secretPath: z.string(),
  envId: z.string().uuid(),
  policy: z.enum(["auto-approve", "requires-approval", "blocked"]).default("auto-approve"),
  approverEmails: z.string().array().nullable().optional(),
  approvalTimeoutSeconds: z.number().default(300),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type TSecretAiPolicies = z.infer<typeof SecretAiPoliciesSchema>;
export type TSecretAiPoliciesInsert = Omit<z.input<typeof SecretAiPoliciesSchema>, TImmutableDBKeys>;
export type TSecretAiPoliciesUpdate = Partial<Omit<z.input<typeof SecretAiPoliciesSchema>, TImmutableDBKeys>>;
