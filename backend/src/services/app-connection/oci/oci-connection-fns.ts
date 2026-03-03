import { AppConnection } from "@app/services/app-connection/app-connection-enums";
import { APP_CONNECTION_NAME_MAP } from "@app/services/app-connection/app-connection-maps";
import { BadRequestError } from "@app/lib/errors";

import { OCIConnectionMethod } from "./oci-connection-enums";

export const getOCIConnectionListItem = () => ({
  name: APP_CONNECTION_NAME_MAP[AppConnection.OCI] as const,
  app: AppConnection.OCI as const,
  methods: Object.values(OCIConnectionMethod)
});

export const validateOCIConnectionCredentials = async () => {
  throw new BadRequestError({ message: "OCI connections are an enterprise feature." });
};
