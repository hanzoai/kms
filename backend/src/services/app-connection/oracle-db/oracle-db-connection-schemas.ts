import { z } from "zod";

import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import { BaseAppConnectionSchema } from "@app/services/app-connection/app-connection-schemas";
import { APP_CONNECTION_NAME_MAP } from "@app/services/app-connection/app-connection-maps";

import { OracleDBConnectionMethod } from "./oracle-db-connection-enums";

const OracleDBConnectionCredentialsSchema = z.object({
  host: z.string().optional(),
  port: z.coerce.number().optional(),
  database: z.string().optional(),
  username: z.string().optional(),
  password: z.string().optional()
});

export const ValidateOracleDBConnectionCredentialsSchema = z.discriminatedUnion("method", [
  z.object({
    method: z.literal(OracleDBConnectionMethod.UsernameAndPassword),
    credentials: OracleDBConnectionCredentialsSchema
  })
]);

const BaseOracleDBConnectionSchema = BaseAppConnectionSchema.extend({
  app: z.literal(AppConnection.OracleDB)
});

export const SanitizedOracleDBConnectionSchema = z.discriminatedUnion("method", [
  BaseOracleDBConnectionSchema.extend({
    method: z.literal(OracleDBConnectionMethod.UsernameAndPassword),
    credentials: z.object({
      host: z.string().optional(),
      port: z.number().optional(),
      database: z.string().optional(),
      username: z.string().optional()
    })
  }).describe(
    JSON.stringify({ title: `${APP_CONNECTION_NAME_MAP[AppConnection.OracleDB]} (Username & Password)` })
  )
]);

export const OracleDBConnectionListItemSchema = z
  .object({
    name: z.literal("OracleDB"),
    app: z.literal(AppConnection.OracleDB),
    methods: z.nativeEnum(OracleDBConnectionMethod).array()
  })
  .describe(JSON.stringify({ title: APP_CONNECTION_NAME_MAP[AppConnection.OracleDB] }));

export type TValidateOracleDBConnectionCredentialsSchema = typeof ValidateOracleDBConnectionCredentialsSchema;
