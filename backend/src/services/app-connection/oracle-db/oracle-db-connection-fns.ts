import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import { APP_CONNECTION_NAME_MAP } from "@app/services/app-connection/app-connection-maps";
import { BadRequestError } from "@app/lib/errors";

import { OracleDBConnectionMethod } from "./oracle-db-connection-enums";

export const getOracleDBConnectionListItem = () => ({
  name: APP_CONNECTION_NAME_MAP[AppConnection.OracleDB] as const,
  app: AppConnection.OracleDB as const,
  methods: Object.values(OracleDBConnectionMethod)
});

export const validateOracleDBConnectionCredentials = async () => {
  throw new BadRequestError({ message: "OracleDB connections are an enterprise feature." });
};
