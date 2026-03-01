// MIT License
// Stub type definitions for HSM (Hardware Security Module) service.

export type THsmServiceFactory = {
  isActive: () => boolean;
  encrypt: (data: Buffer) => Promise<Buffer>;
  decrypt: (data: Buffer) => Promise<Buffer>;
};

export enum HsmModule {
  PKCS11 = "pkcs11"
}

export enum THsmStatus {
  EXTERNAL = "external",
  INTERNAL = "internal"
}
