import { BadRequestError } from "@app/lib/errors";

export const ChefSyncFns = {
  syncSecrets: async () => {
    throw new BadRequestError({ message: "Chef sync is an enterprise feature." });
  },
  getSecrets: async () => {
    throw new BadRequestError({ message: "Chef sync is an enterprise feature." });
  },
  removeSecrets: async () => {
    throw new BadRequestError({ message: "Chef sync is an enterprise feature." });
  }
};
