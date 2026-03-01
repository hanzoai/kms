import { logger } from "@app/lib/logger";
import { OrgServiceActor } from "@app/lib/types";
import { KvVersion } from "@app/services/external-migration/external-migration-types";

import { AppConnection } from "../app-connection-enums";
import { listHCVaultMounts } from "./hc-vault-connection-fns";
import { THCVaultConnection } from "./hc-vault-connection-types";

type TGetAppConnectionFunc = (
  app: AppConnection,
  connectionId: string,
  actor: OrgServiceActor
) => Promise<THCVaultConnection>;

export const hcVaultConnectionService = (
  getAppConnection: TGetAppConnectionFunc,
  gatewayService?: unknown,
  gatewayV2Service?: unknown
) => {
  const listMounts = async (connectionId: string, actor: OrgServiceActor) => {
    const appConnection = await getAppConnection(AppConnection.HCVault, connectionId, actor);

    try {
      const mounts = await listHCVaultMounts(appConnection, gatewayService, gatewayV2Service);
      // Filter for KV mounts (v1 and v2) and extract just the paths
      return mounts
        .filter((mount) => mount.type === "kv" && (mount.version === KvVersion.V2 || mount.version === KvVersion.V1))
        .map((mount) => mount.path);
    } catch (error) {
      logger.error(error, "Failed to establish connection with Hashicorp Vault");
      return [];
    }
  };

  return {
    listMounts
  };
};
