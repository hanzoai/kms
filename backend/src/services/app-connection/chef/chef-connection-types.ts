import { z } from "zod";
import { ValidateChefConnectionCredentialsSchema } from "./chef-connection-schemas";

export type TChefConnection = {
  app: "chef";
  method: "user-key";
  credentials: {
    serverUrl?: string;
    userId?: string;
    userKey?: string;
    organizationName?: string;
  };
};

export type TChefConnectionConfig = TChefConnection;
export type TChefConnectionInput = TChefConnection;
export type TValidateChefConnectionCredentialsSchema = z.infer<typeof ValidateChefConnectionCredentialsSchema>;
