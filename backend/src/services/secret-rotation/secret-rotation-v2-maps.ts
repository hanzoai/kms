import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import { SecretRotation } from "./secret-rotation-v2-enums";

export const SECRET_ROTATION_NAME_MAP: Record<SecretRotation, string> = {
  [SecretRotation.PostgresCredentials]: "PostgreSQL Credentials",
  [SecretRotation.MsSqlCredentials]: "MSSQL Credentials",
  [SecretRotation.MySqlCredentials]: "MySQL Credentials"
};

export const SECRET_ROTATION_CONNECTION_MAP: Record<SecretRotation, AppConnection> = {
  [SecretRotation.PostgresCredentials]: AppConnection.Postgres,
  [SecretRotation.MsSqlCredentials]: AppConnection.MsSql,
  [SecretRotation.MySqlCredentials]: AppConnection.MySql
};
