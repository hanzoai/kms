// Community edition: secret scanning v2 webhooks are not available.
export const registerSecretScanningV2Webhooks = async (_server: FastifyZodProvider) => {
  // No-op in CE: secret scanning is an EE feature.
};
