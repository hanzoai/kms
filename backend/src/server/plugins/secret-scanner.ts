// Community edition: secret scanning v1 webhooks are not available.
export const registerSecretScannerGhApp = async (_server: FastifyZodProvider) => {
  // No-op in CE: secret scanning is an EE feature.
};
