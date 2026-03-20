import { z } from "zod";

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
  // GET /organization/permissions — returns full admin permissions
  server.route({
    method: "GET",
    url: "/permissions",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async (req) => {
      // Return admin-level permissions (all actions allowed)
      return {
        permissions: [
          {
            action: ["manage"],
            subject: "all",
            conditions: undefined
          }
        ],
        memberships: [
          {
            id: "self-hosted-membership",
            role: "admin",
            roles: [{ role: "admin" }],
            orgId: (req as any).permission?.orgId || "unknown",
            userId: (req as any).permission?.id || "unknown",
            status: "accepted",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      };
    }
  });
};

import type { FastifyZodProvider } from "@app/server/plugins/fastify-zod";
