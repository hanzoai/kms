import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import { APP_CONNECTION_NAME_MAP } from "@app/services/app-connection/app-connection-maps";
import { BadRequestError } from "@app/lib/errors";

import { ChefConnectionMethod } from "./chef-connection-enums";

export const getChefConnectionListItem = () => ({
  name: APP_CONNECTION_NAME_MAP[AppConnection.Chef] as const,
  app: AppConnection.Chef as const,
  methods: Object.values(ChefConnectionMethod)
});

export const validateChefConnectionCredentials = async () => {
  throw new BadRequestError({ message: "Chef connections are an enterprise feature." });
};

// Stub functions for Chef data bag operations used by pki-sync
export type TChefDataBagItemContent = Record<string, unknown>;

export const listChefDataBagItems = async (..._args: unknown[]) => {
  throw new BadRequestError({ message: "Chef data bag operations are an enterprise feature." });
};

export const createChefDataBagItem = async (..._args: unknown[]) => {
  throw new BadRequestError({ message: "Chef data bag operations are an enterprise feature." });
};

export const updateChefDataBagItem = async (..._args: unknown[]) => {
  throw new BadRequestError({ message: "Chef data bag operations are an enterprise feature." });
};

export const removeChefDataBagItem = async (..._args: unknown[]) => {
  throw new BadRequestError({ message: "Chef data bag operations are an enterprise feature." });
};
