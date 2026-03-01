// MIT License
// Community edition: HSM is disabled. Stubs satisfy the interface.

import crypto from "node:crypto";

export type THsmServiceFactory = ReturnType<typeof hsmServiceFactory>;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const hsmServiceFactory = (_opts?: { hsmModule?: any; envConfig?: any }) => {
  const isActive = () => false;

  const startService = async () => {};

  const encrypt = async (_data: Buffer): Promise<Buffer> => {
    throw new Error("HSM not configured");
  };

  const decrypt = async (_data: Buffer): Promise<Buffer> => {
    throw new Error("HSM not configured");
  };

  const randomBytes = async (size: number): Promise<Buffer> => {
    return crypto.randomBytes(size);
  };

  return { isActive, encrypt, decrypt, startService, randomBytes };
};
