import { z } from "zod";

// Stub schema for stripped EE secret rotation feature
export const SecretRotationV2Schema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  description: z.string().optional().nullable(),
  type: z.string(),
  status: z.string().optional().nullable(),
  statusMessage: z.string().optional().nullable(),
  lastRotatedAt: z.date().optional().nullable(),
  isAutoRotationEnabled: z.boolean().optional(),
  rotationInterval: z.number().optional()
});

export type TSqlCredentialsRotationGeneratedCredentials = Record<string, unknown>;
export type TSqlCredentialsRotationWithConnection = Record<string, unknown>;
