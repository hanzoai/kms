import { z } from "zod";

import { readLimit } from "@app/server/config/rateLimiter";
import { verifyAuth } from "@app/server/plugins/auth/verify-auth";
import { AuthMode } from "@app/services/auth/auth-type";

/**
 * Stub plan router for self-hosted / open-source KMS.
 * Returns an enterprise-tier plan with all features enabled and no limits,
 * preventing the frontend from crashing on 404 when it fetches the plan.
 */
export const registerOrganizationPlanRouter = async (server: FastifyZodProvider) => {
  const SELF_HOSTED_PLAN = {
    id: "self-hosted",
    membersUsed: 0,
    memberLimit: -1,
    identitiesUsed: 0,
    identityLimit: -1,
    auditLogs: true,
    dynamicSecret: true,
    auditLogsRetentionDays: 365,
    auditLogStreamLimit: -1,
    auditLogStreams: true,
    customAlerts: true,
    customRateLimits: true,
    pitRecovery: true,
    githubOrgSync: true,
    subOrganization: true,
    ipAllowlisting: true,
    rbac: true,
    secretVersioning: true,
    slug: "enterprise",
    secretApproval: true,
    secretRotation: true,
    tier: 3,
    workspaceLimit: -1,
    workspacesUsed: 0,
    environmentLimit: -1,
    samlSSO: true,
    sshHostGroups: true,
    secretAccessInsights: true,
    hsm: true,
    oidcSSO: true,
    scim: true,
    ldap: true,
    groups: true,
    status: "active" as const,
    trial_end: null,
    has_used_trial: true,
    caCrl: true,
    instanceUserManagement: true,
    gateway: true,
    externalKms: true,
    pkiEst: true,
    pkiAcme: true,
    pkiLegacyTemplates: true,
    enforceMfa: true,
    enforceGoogleSSO: true,
    projectTemplates: true,
    kmip: true,
    secretScanning: true,
    enterpriseSecretSyncs: true,
    enterpriseCertificateSyncs: true,
    enterpriseAppConnections: true,
    machineIdentityAuthTemplates: true,
    secretShareExternalBranding: true
  };

  server.route({
    method: "GET",
    url: "/:organizationId/plan",
    config: {
      rateLimit: readLimit
    },
    schema: {
      params: z.object({
        organizationId: z.string().trim()
      }),
      querystring: z.object({
        refreshCache: z.string().optional()
      })
    },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async () => {
      return { plan: SELF_HOSTED_PLAN };
    }
  });

  server.route({
    method: "GET",
    url: "/:organizationId/plan/billing",
    config: {
      rateLimit: readLimit
    },
    schema: {
      params: z.object({
        organizationId: z.string().trim()
      })
    },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async () => {
      return { billing: null };
    }
  });

  server.route({
    method: "GET",
    url: "/:organizationId/plan/table",
    config: {
      rateLimit: readLimit
    },
    schema: {
      params: z.object({
        organizationId: z.string().trim()
      })
    },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async () => {
      return { plan: SELF_HOSTED_PLAN };
    }
  });

  server.route({
    method: "GET",
    url: "/:organizationId/plans/table",
    config: {
      rateLimit: readLimit
    },
    schema: {
      params: z.object({
        organizationId: z.string().trim()
      }),
      querystring: z.object({
        billingCycle: z.string().optional()
      })
    },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async () => {
      return { plans: [SELF_HOSTED_PLAN] };
    }
  });
};

// Need the type import for the server parameter
import type { FastifyZodProvider } from "@app/server/plugins/fastify-zod";
