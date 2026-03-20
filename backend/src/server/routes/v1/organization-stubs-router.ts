import { readLimit } from "@app/server/config/rateLimiter";
import { verifyAuth } from "@app/server/plugins/auth/verify-auth";
import { AuthMode } from "@app/services/auth/auth-type";

/**
 * Stub routes for EE endpoints that the frontend calls but are missing
 * in the open-source / self-hosted KMS build.
 *
 * Returns permissive defaults so the UI doesn't crash on 404 / 403.
 */
export const registerOrganizationStubsRouter = async (server: FastifyZodProvider) => {
  // GET /organization/permissions — returns full admin permissions in CASL packed format
  server.route({
    method: "GET",
    url: "/permissions",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async () => {
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

  // GET /organization/roles — returns empty roles (EE feature: custom roles)
  server.route({
    method: "GET",
    url: "/roles",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async () => {
      return { data: { roles: [] } };
    }
  });

};

/**
 * Stub routes for EE endpoints registered under other prefixes.
 * These handle 404s for features like gateways, SCIM, SSO config, etc.
 */
export const registerEeStubRoutes = async (server: FastifyZodProvider) => {
  // --- Gateways (EE) ---
  server.route({
    method: "GET",
    url: "/gateways",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ gateways: [] })
  });

  // --- External KMS (EE) ---
  server.route({
    method: "GET",
    url: "/external-kms",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ externalKms: [] })
  });

  // --- Audit Log Streams (EE) ---
  server.route({
    method: "GET",
    url: "/audit-log-streams",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ auditLogStreams: [] })
  });

  // --- Project Templates (EE) ---
  server.route({
    method: "GET",
    url: "/project-templates",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ projectTemplates: [] })
  });

  // --- Sub-Organizations (EE) ---
  server.route({
    method: "GET",
    url: "/sub-organizations",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ organizations: [], totalCount: 0 })
  });

  // --- GitHub Org Sync Config (EE) ---
  server.route({
    method: "GET",
    url: "/github-org-sync-config",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ gitHubOrgSyncConfig: null })
  });

  // --- SSO Config (EE) ---
  server.route({
    method: "GET",
    url: "/sso/config",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({
      id: "",
      organization: "",
      orgId: "",
      authProvider: "",
      isActive: false,
      entryPoint: "",
      issuer: "",
      cert: "",
      lastUsed: null
    })
  });

  // --- SSO OIDC Config (EE) ---
  server.route({
    method: "GET",
    url: "/sso/oidc/config",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({
      id: "",
      issuer: "",
      authorizationEndpoint: "",
      configurationType: "",
      discoveryURL: "",
      jwksUri: "",
      tokenEndpoint: "",
      userinfoEndpoint: "",
      isActive: false,
      orgId: "",
      allowedEmailDomains: ""
    })
  });

  // --- LDAP Config (EE) ---
  server.route({
    method: "GET",
    url: "/ldap/config",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({
      id: "",
      organization: "",
      isActive: false,
      url: "",
      bindDN: "",
      bindPass: "",
      searchBase: "",
      searchFilter: "",
      groupSearchBase: "",
      groupSearchFilter: "",
      caCert: ""
    })
  });

  // --- SCIM tokens (EE) ---
  server.route({
    method: "GET",
    url: "/scim/scim-tokens",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ scimTokens: [] })
  });

  // --- Identity Templates (EE) ---
  server.route({
    method: "GET",
    url: "/identity-templates/search",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ identityTemplates: [], totalCount: 0 })
  });

  // --- Secret Approval Requests (EE) ---
  server.route({
    method: "GET",
    url: "/secret-approval-requests/count",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ approvals: { open: 0, closed: 0 } })
  });

  // --- Access Approval Policies (EE) ---
  server.route({
    method: "GET",
    url: "/access-approvals/policies",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ data: { policies: [] } })
  });

  // --- Access Approval Requests Count (EE) ---
  server.route({
    method: "GET",
    url: "/access-approvals/requests/count",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ count: { open: 0, closed: 0 } })
  });

  // --- Relays (EE) ---
  server.route({
    method: "GET",
    url: "/relays",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ relays: [] })
  });

  // --- Secret Rotations (EE) ---
  server.route({
    method: "GET",
    url: "/secret-rotations",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ secretRotations: [] })
  });

  // --- PIT Commits Count (EE) ---
  server.route({
    method: "GET",
    url: "/pit/commits/count",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ count: 0, folderId: "" })
  });

  // --- PIT Commits (EE) ---
  server.route({
    method: "GET",
    url: "/pit/commits",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ commits: [], total: 0, hasMore: false })
  });
};

/**
 * Stub routes for EE endpoints under /organizations/:organizationId prefix
 */
export const registerOrganizationsStubsRouter = async (server: FastifyZodProvider) => {
  // --- Licenses (EE/Cloud) ---
  server.route({
    method: "GET",
    url: "/:organizationId/licenses",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ licenses: [] })
  });

  // --- Invoices (EE/Cloud) ---
  server.route({
    method: "GET",
    url: "/:organizationId/invoices",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ invoices: [] })
  });

  // --- Billing Details (EE/Cloud) ---
  server.route({
    method: "GET",
    url: "/:organizationId/billing-details",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ name: "", email: "" })
  });

  // --- Payment Methods (EE/Cloud) ---
  server.route({
    method: "GET",
    url: "/:organizationId/billing-details/payment-methods",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ pmtMethods: [] })
  });

  // --- Tax IDs (EE/Cloud) ---
  server.route({
    method: "GET",
    url: "/:organizationId/billing-details/tax-ids",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ tax_ids: { data: [] } })
  });

  // --- Customer Portal Session (EE/Cloud) ---
  server.route({
    method: "POST",
    url: "/:organizationId/customer-portal-session",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ url: "" })
  });
};

/**
 * Stub routes for project-level EE endpoints (e.g. project permissions)
 */
export const registerProjectStubsRouter = async (server: FastifyZodProvider) => {
  // GET /projects/:projectId/permissions — returns full admin permissions (CASL packed format)
  server.route({
    method: "GET",
    url: "/:projectId/permissions",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => {
      const packedPermissions = [["manage", "all"]];
      return {
        data: {
          permissions: packedPermissions,
          memberships: [
            {
              id: "self-hosted-membership",
              roles: [{ role: "admin" }],
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString()
            }
          ]
        }
      };
    }
  });
};

/**
 * Stub routes for project-level EE endpoints (roles, KMS, snapshots, PIT, workflow integrations)
 */
export const registerProjectEeStubRoutes = async (server: FastifyZodProvider) => {
  // --- Project Roles (EE: custom roles) ---
  server.route({
    method: "GET",
    url: "/:projectId/roles",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({
      roles: [
        { id: "admin", name: "Admin", slug: "admin", description: "Full access" },
        { id: "member", name: "Member", slug: "member", description: "Limited access" },
        { id: "viewer", name: "Viewer", slug: "viewer", description: "Read-only access" },
        { id: "no-access", name: "No Access", slug: "no-access", description: "No access" }
      ]
    })
  });

  // --- Project KMS Config (EE: external KMS) ---
  server.route({
    method: "GET",
    url: "/:projectId/kms",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({
      secretManagerKmsKey: {
        id: "internal",
        name: "Default KMS",
        isExternal: false
      }
    })
  });

  // --- Project KMS Backup (EE) ---
  server.route({
    method: "GET",
    url: "/:projectId/kms/backup",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ secretManager: "" })
  });


  // --- Secret Snapshots Count (EE) ---
  server.route({
    method: "GET",
    url: "/:projectId/secret-snapshots/count",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ count: 0 })
  });

  // --- PIT Commits Count (EE) ---
  server.route({
    method: "GET",
    url: "/:projectId/pit/commits/count",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ count: 0 })
  });

  // --- PIT Commits (EE) ---
  server.route({
    method: "GET",
    url: "/:projectId/pit/commits",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ commits: [] })
  });
};

/**
 * Stub routes for EE v2 endpoints (gateways, secret approvals)
 */
export const registerV2EeStubRoutes = async (server: FastifyZodProvider) => {
  server.route({
    method: "GET",
    url: "/gateways",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ gateways: [] })
  });

  // --- Secret Approval Policies (EE) ---
  server.route({
    method: "GET",
    url: "/secret-approvals",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ approvals: [] })
  });

  // --- Secret Approvals Board (EE) ---
  server.route({
    method: "GET",
    url: "/secret-approvals/board",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ policy: null })
  });

  // --- Secret Approval Requests (EE) ---
  server.route({
    method: "GET",
    url: "/secret-approval-requests",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ approvals: [] })
  });

  // --- Secret Approval Requests Count (EE) ---
  server.route({
    method: "GET",
    url: "/secret-approval-requests/count",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    handler: async () => ({ approvals: { open: 0, closed: 0 } })
  });
};
