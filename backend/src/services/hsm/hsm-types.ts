// Minimal HSM types for KMS
// This is a stub implementation - full enterprise HSM features removed

export interface HsmModule {
  // Stub interface for HSM module
  initialize: () => void;
  finalize: () => void;
  getModule: () => any;
}