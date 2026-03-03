import { z } from "zod";

import { SecretSync } from "@app/services/secret-sync/secret-sync-enums";

export const ChefSyncSchema = z.object({ destination: z.literal(SecretSync.Chef) });
export const ChefSyncListItemSchema = z.object({ destination: z.literal(SecretSync.Chef) });
