import fp from "fastify-plugin";

// Community edition: assume-privilege feature is not available.
export const injectAssumePrivilege = fp(async (_server: FastifyZodProvider) => {
  // No-op in CE: privilege assumption is an EE feature.
});
