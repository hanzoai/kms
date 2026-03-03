// Stub: Secret rotation maps stripped during EE removal.
// Empty maps prevent runtime ReferenceErrors while keeping the API surface intact.

import { AppConnection } from "@app/services/app-connection/app-connection-enums";

export type SecretRotation = string;

export const SECRET_ROTATION_CONNECTION_MAP: Record<string, AppConnection> = {};
export const SECRET_ROTATION_NAME_MAP: Record<string, string> = {};
