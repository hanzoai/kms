// Runtime environment variables loaded from server.
// The window body is filled with value from the server.
// We add a script in index.html to load it from server before react loads.
/* eslint-disable no-underscore-dangle */
export const envConfig = {
  ENV: import.meta.env.MODE,
  get CAPTCHA_SITE_KEY() {
    return (
      window?.__KMS_RUNTIME_ENV__?.CAPTCHA_SITE_KEY || import.meta.env.VITE_CAPTCHA_SITE_KEY
    );
  },
  get TELEMETRY_CAPTURING_ENABLED() {
    return false;
  },

  get PLATFORM_VERSION() {
    return import.meta.env.VITE_KMS_PLATFORM_VERSION;
  }
};
