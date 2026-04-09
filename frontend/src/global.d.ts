export {};

declare global {
  interface Window {
    __KMS_RUNTIME_ENV__?: {
      CAPTCHA_SITE_KEY?: string;
      TELEMETRY_CAPTURING_ENABLED: string;
    };
  }
}
