import { BadRequestError } from "@app/lib/errors";

export const OCIVaultSyncFns = {
  syncSecrets: async () => {
    throw new BadRequestError({ message: "OCI Vault sync is an enterprise feature." });
  },
  getSecrets: async () => {
    throw new BadRequestError({ message: "OCI Vault sync is an enterprise feature." });
  },
  removeSecrets: async () => {
    throw new BadRequestError({ message: "OCI Vault sync is an enterprise feature." });
  }
};
