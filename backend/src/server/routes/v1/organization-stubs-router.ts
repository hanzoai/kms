import { packRules } from "@casl/ability/extra";

import { readLimit } from "@app/server/config/rateLimiter";
import { verifyAuth } from "@app/server/plugins/auth/verify-auth";
import { AuthMode } from "@app/services/auth/auth-type";

import type { FastifyZodProvider } from "@app/server/plugins/fastify-zod";

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
    handler: async (req) => {
      // Pack the admin rule using CASL's packRules format
      // packRules converts {action, subject, conditions, inverted} objects to tuple arrays
      const packedPermissions = packRules([
        { action: "manage", subject: "all" }
      ]);

      return {
        permissions: packedPermissions,
        membership: {
          id: "self-hosted-membership",
          role: "admin",
          roles: [{ role: "admin" }],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
      };
    }
  });
};
