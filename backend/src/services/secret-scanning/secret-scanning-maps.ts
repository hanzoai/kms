import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import { SecretScanningDataSource } from "./secret-scanning-enums";

export const SECRET_SCANNING_DATA_SOURCE_NAME_MAP: Record<SecretScanningDataSource, string> = {
  [SecretScanningDataSource.GitHub]: "GitHub"
};

export const SECRET_SCANNING_DATA_SOURCE_CONNECTION_MAP: Record<SecretScanningDataSource, AppConnection> = {
  [SecretScanningDataSource.GitHub]: AppConnection.GitHubRadar
};

export const AUTO_SYNC_DESCRIPTION_HELPER: Record<
  SecretScanningDataSource,
  { verb: string; noun: string }
> = {
  [SecretScanningDataSource.GitHub]: { verb: "push", noun: "repositories" }
};
