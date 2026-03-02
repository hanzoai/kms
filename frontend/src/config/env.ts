// akhilmhdh: These are runtime environment variables loaded from server
// The window body is filled with value from the server
// We add a script in index.html to load it from server before react loads
/* eslint-disable no-underscore-dangle */
export const envConfig = {
  ENV: import.meta.env.MODE,
  get CAPTCHA_SITE_KEY() {
    return (
      window?.__KMS_RUNTIME_ENV__?.CAPTCHA_SITE_KEY || import.meta.env.VITE_CAPTCHA_SITE_KEY
    );
  },
  get INTERCOM_ID() {
    return window?.__KMS_RUNTIME_ENV__?.INTERCOM_ID || import.meta.env.VITE_INTERCOM_ID;
  },
  get INSIGHTS_API_KEY() {
    return (
      window?.__KMS_RUNTIME_ENV__?.INSIGHTS_API_KEY ||
      import.meta.env.VITE_INSIGHTS_API_KEY ||
      window?.__KMS_RUNTIME_ENV__?.POSTHOG_API_KEY ||
      import.meta.env.VITE_POSTHOG_API_KEY
    );
  },
  get INSIGHTS_HOST() {
    return (
      import.meta.env.VITE_INSIGHTS_HOST ||
      import.meta.env.VITE_POSTHOG_HOST ||
      "https://insights.hanzo.ai"
    );
  },
  get TELEMETRY_CAPTURING_ENABLED() {
    return (
      window?.__KMS_RUNTIME_ENV__?.TELEMETRY_CAPTURING_ENABLED ||
      import.meta.env.VITE_TELEMETRY_CAPTURING_ENABLED === true
    );
  },

  get PLATFORM_VERSION() {
    return import.meta.env.VITE_KMS_PLATFORM_VERSION;
  }
};
