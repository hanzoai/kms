import { z } from "zod";
import { ValidateOracleDBConnectionCredentialsSchema } from "./oracle-db-connection-schemas";

export type TOracleDBConnection = {
  app: "oracledb";
  method: "username-and-password";
  credentials: {
    host?: string;
    port?: number;
    database?: string;
    username?: string;
    password?: string;
  };
};

export type TOracleDBConnectionInput = TOracleDBConnection;
export type TValidateOracleDBConnectionCredentialsSchema = z.infer<typeof ValidateOracleDBConnectionCredentialsSchema>;
