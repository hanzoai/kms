import { insights } from "@hanzo/insights";

import { envConfig } from "@app/config/env";

export const initInsights = () => {
  try {
    if (typeof window !== "undefined") {
      if (
        envConfig.ENV === "production" &&
        envConfig.TELEMETRY_CAPTURING_ENABLED === true &&
        envConfig.INSIGHTS_API_KEY
      ) {
        insights.init(envConfig.INSIGHTS_API_KEY, {
          api_host: envConfig.INSIGHTS_HOST
        });
      }
    }

    return insights;
  } catch (e) {
    console.log("insights err", e);
  }

  return undefined;
};
