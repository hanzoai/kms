import { z } from "zod";
import { ValidateOCIConnectionCredentialsSchema } from "./oci-connection-schemas";

export type TOCIConnection = {
  app: "oci";
  method: "access-key";
  credentials: {
    tenancyOcid?: string;
    userOcid?: string;
    region?: string;
    fingerprint?: string;
    privateKey?: string;
  };
};

export type TOCIConnectionConfig = TOCIConnection;
export type TOCIConnectionInput = TOCIConnection;
export type TValidateOCIConnectionCredentialsSchema = z.infer<typeof ValidateOCIConnectionCredentialsSchema>;
