import { z } from "zod";

import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import { BaseAppConnectionSchema } from "@app/services/app-connection/app-connection-schemas";
import { APP_CONNECTION_NAME_MAP } from "@app/services/app-connection/app-connection-maps";

import { OCIConnectionMethod } from "./oci-connection-enums";

const OCIConnectionCredentialsSchema = z.object({
  tenancyOcid: z.string().optional(),
  userOcid: z.string().optional(),
  region: z.string().optional(),
  fingerprint: z.string().optional(),
  privateKey: z.string().optional()
});

export const ValidateOCIConnectionCredentialsSchema = z.discriminatedUnion("method", [
  z.object({
    method: z.literal(OCIConnectionMethod.AccessKey),
    credentials: OCIConnectionCredentialsSchema
  })
]);

const BaseOCIConnectionSchema = BaseAppConnectionSchema.extend({
  app: z.literal(AppConnection.OCI)
});

export const SanitizedOCIConnectionSchema = z.discriminatedUnion("method", [
  BaseOCIConnectionSchema.extend({
    method: z.literal(OCIConnectionMethod.AccessKey),
    credentials: z.object({
      tenancyOcid: z.string().optional(),
      userOcid: z.string().optional(),
      region: z.string().optional()
    })
  }).describe(JSON.stringify({ title: `${APP_CONNECTION_NAME_MAP[AppConnection.OCI]} (Access Key)` }))
]);

export const OCIConnectionListItemSchema = z
  .object({
    name: z.literal("OCI"),
    app: z.literal(AppConnection.OCI),
    methods: z.nativeEnum(OCIConnectionMethod).array()
  })
  .describe(JSON.stringify({ title: APP_CONNECTION_NAME_MAP[AppConnection.OCI] }));

export type TValidateOCIConnectionCredentialsSchema = typeof ValidateOCIConnectionCredentialsSchema;
