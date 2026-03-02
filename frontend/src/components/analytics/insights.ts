import posthog from "posthog-js";

import { envConfig } from "@app/config/env";

export const initInsights = () => {
  console.log("Hi there 👋");
  try {
    if (typeof window !== "undefined") {
      if (
        envConfig.ENV === "production" &&
        envConfig.TELEMETRY_CAPTURING_ENABLED === true &&
        envConfig.INSIGHTS_API_KEY
      ) {
        posthog.init(envConfig.INSIGHTS_API_KEY, {
          api_host: envConfig.INSIGHTS_HOST
        });
      }
    }

    return posthog;
  } catch (e) {
    console.log("insights err", e);
  }

  return undefined;
};
