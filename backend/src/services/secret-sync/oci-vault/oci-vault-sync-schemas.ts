import { z } from "zod";

import { SecretSync } from "@app/services/secret-sync/secret-sync-enums";

export const OCIVaultSyncSchema = z.object({ destination: z.literal(SecretSync.OCIVault) });
export const OCIVaultSyncListItemSchema = z.object({ destination: z.literal(SecretSync.OCIVault) });
