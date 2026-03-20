import { readLimit } from "@app/server/config/rateLimiter";
import { verifyAuth } from "@app/server/plugins/auth/verify-auth";
import { AuthMode } from "@app/services/auth/auth-type";

/**
 * Stub routes for EE endpoints that the frontend calls but are missing
 * in the open-source / self-hosted KMS build.
 *
 * Returns permissive defaults so the UI doesn't crash on 404.
 */
export const registerOrganizationStubsRouter = async (server: FastifyZodProvider) => {
  // GET /organization/permissions — returns full admin permissions in CASL packed format
  server.route({
    method: "GET",
    url: "/permissions",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async () => {
      // CASL packRules format: each rule is a tuple [action, subject, conditions?, inverted?]
      // "manage" + "all" grants full admin access
      const packedPermissions = [["manage", "all"]];

      return {
        permissions: packedPermissions,
        memberships: [
          {
            id: "self-hosted-membership",
            role: "admin",
            roles: [{ role: "admin" }],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      };
    }
  });
};
