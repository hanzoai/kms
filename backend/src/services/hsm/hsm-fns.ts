// MIT License
// Community edition: HSM is not active.

import type { THsmServiceFactory } from "./hsm-service";
import type { TKmsRootConfigDALFactory } from "@app/services/kms/kms-root-config-dal";

export const isHsmActiveAndEnabled = async (_opts?: {
  hsmService?: THsmServiceFactory;
  kmsRootConfigDAL?: TKmsRootConfigDALFactory;
  licenseService?: unknown;
}) => ({
  isHsmConfigured: false,
  isHsmActive: false,
  rootKmsConfigEncryptionStrategy: null as null | string
});

export const initializeHsmModule = (_envConfig: unknown) => {
  return {
    initialize: () => {},
    isInitialized: false,
    getModule: () => undefined as unknown,
    finalize: () => {}
  };
};

