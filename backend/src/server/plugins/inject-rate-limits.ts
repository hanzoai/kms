import fp from "fastify-plugin";

// Default rate limits for the community edition.
const DEFAULT_RATE_LIMITS = {
  readLimit: 60,
  writeLimit: 200,
  secretsLimit: 40,
  publicEndpointLimit: 30,
  authRateLimit: 60,
  inviteUserRateLimit: 30,
  mfaRateLimit: 20,
  identityCreationLimit: 30,
  projectCreationLimit: 5
};

export const injectRateLimits = fp(async (server) => {
  server.decorateRequest("rateLimits", null);
  server.addHook("onRequest", async (req) => {
    // Community edition: always use the static default rate limits.
    // EE allows custom per-org rate limits via the license plan.
    req.rateLimits = DEFAULT_RATE_LIMITS;
  });
});
