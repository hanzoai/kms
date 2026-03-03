import { z } from "zod";

import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import { BaseAppConnectionSchema } from "@app/services/app-connection/app-connection-schemas";
import { APP_CONNECTION_NAME_MAP } from "@app/services/app-connection/app-connection-maps";

import { ChefConnectionMethod } from "./chef-connection-enums";

const ChefConnectionCredentialsSchema = z.object({
  serverUrl: z.string().optional(),
  userId: z.string().optional(),
  userKey: z.string().optional(),
  organizationName: z.string().optional()
});

export const ValidateChefConnectionCredentialsSchema = z.discriminatedUnion("method", [
  z.object({
    method: z.literal(ChefConnectionMethod.UserKey),
    credentials: ChefConnectionCredentialsSchema
  })
]);

const BaseChefConnectionSchema = BaseAppConnectionSchema.extend({
  app: z.literal(AppConnection.Chef)
});

export const SanitizedChefConnectionSchema = z.discriminatedUnion("method", [
  BaseChefConnectionSchema.extend({
    method: z.literal(ChefConnectionMethod.UserKey),
    credentials: z.object({
      serverUrl: z.string().optional(),
      userId: z.string().optional(),
      organizationName: z.string().optional()
    })
  }).describe(JSON.stringify({ title: `${APP_CONNECTION_NAME_MAP[AppConnection.Chef]} (User Key)` }))
]);

export const ChefConnectionListItemSchema = z
  .object({
    name: z.literal("Chef"),
    app: z.literal(AppConnection.Chef),
    methods: z.nativeEnum(ChefConnectionMethod).array()
  })
  .describe(JSON.stringify({ title: APP_CONNECTION_NAME_MAP[AppConnection.Chef] }));

export type TValidateChefConnectionCredentialsSchema = typeof ValidateChefConnectionCredentialsSchema;
