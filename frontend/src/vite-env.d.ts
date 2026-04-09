/// <reference types="vite/client" />
//
interface ImportMetaEnv {
  readonly VITE_CAPTCHA_SITE_KEY?: string;
  readonly VITE_KMS_PLATFORM_VERSION?: string;
  readonly VITE_TELEMETRY_CAPTURING_ENABLED?: boolean;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
