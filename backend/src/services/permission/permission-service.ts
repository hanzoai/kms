// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Permission service: RBAC engine. Resolves a user/identity's effective
// permissions by reading their membership roles and building a CASL ability.

import { createMongoAbility, MongoAbility, RawRuleOf } from "@casl/ability";
import { unpackRules } from "@casl/ability/extra";

import { ActionProjectType, ActorType as DbActorType, OrgMembershipRole, ProjectMembershipRole } from "@app/db/schemas";
import { conditionsMatcher } from "@app/lib/casl";
import { logger } from "@app/lib/logger";
import { ForbiddenRequestError } from "@app/lib/errors";
import { ActorAuthMethod, ActorType } from "@app/services/auth/auth-type";
import { TServiceTokenDALFactory } from "@app/services/service-token/service-token-dal";
import { TProjectDALFactory } from "@app/services/project/project-dal";
import { TUserDALFactory } from "@app/services/user/user-dal";
import { TIdentityDALFactory } from "@app/services/identity/identity-dal";
import { TKeyStoreFactory } from "@app/keystore/keystore";

import { TPermissionDALFactory } from "./permission-dal";
import { DEFAULT_ORG_ROLE_PERMISSIONS, DEFAULT_PROJECT_ROLE_PERMISSIONS } from "./default-roles";
import { OrgPermissionSet } from "./org-permission";
import { ProjectPermissionSet } from "./project-permission";
import { TRoleDALFactory } from "@app/services/role/role-dal";

// ---------------------------------------------------------------------------
// Factory dependencies
// ---------------------------------------------------------------------------

type TPermissionServiceFactoryDep = {
  permissionDAL: TPermissionDALFactory;
  serviceTokenDAL: TServiceTokenDALFactory;
  projectDAL: Pick<TProjectDALFactory, "findById">;
  keyStore: Pick<TKeyStoreFactory, "getItem" | "setItemWithExpiry">;
  roleDAL: TRoleDALFactory;
  userDAL: Pick<TUserDALFactory, "findById">;
  identityDAL: Pick<TIdentityDALFactory, "findById">;
};

export type TPermissionServiceFactory = ReturnType<typeof permissionServiceFactory>;

// ---------------------------------------------------------------------------
// CASL ability builder helpers
// ---------------------------------------------------------------------------

type ProjectAbility = MongoAbility<ProjectPermissionSet>;
type OrgAbility = MongoAbility<OrgPermissionSet>;

const buildProjectAbility = (rules: RawRuleOf<ProjectAbility>[]): ProjectAbility =>
  createMongoAbility<ProjectAbility>(rules, { conditionsMatcher });

const buildOrgAbility = (rules: RawRuleOf<OrgAbility>[]): OrgAbility =>
  createMongoAbility<OrgAbility>(rules, { conditionsMatcher });

/** Returns the built-in rule set for a project role slug. */
const getDefaultProjectRules = (roleSlug: string): RawRuleOf<ProjectAbility>[] => {
  const rules = DEFAULT_PROJECT_ROLE_PERMISSIONS[roleSlug];
  if (rules) return rules as RawRuleOf<ProjectAbility>[];
  return [];
};

/** Returns the built-in rule set for an org role slug. */
const getDefaultOrgRules = (roleSlug: string): RawRuleOf<OrgAbility>[] => {
  const rules = DEFAULT_ORG_ROLE_PERMISSIONS[roleSlug];
  if (rules) return rules as RawRuleOf<OrgAbility>[];
  return [];
};

// ---------------------------------------------------------------------------
// Service factory
// ---------------------------------------------------------------------------

export const permissionServiceFactory = ({
  permissionDAL,
  serviceTokenDAL,
  projectDAL,
  roleDAL
}: TPermissionServiceFactoryDep) => {
  // ------------------------------------------------------------------
  // Project permission
  // ------------------------------------------------------------------

  /**
   * Builds a CASL ability for the given actor in the given project.
   * Supports USER, IDENTITY, and SERVICE actor types.
   */
  const getProjectPermission = async ({
    actor,
    actorId,
    projectId,
    actorAuthMethod,
    actorOrgId,
    actionProjectType: _actionProjectType
  }: {
    actor: ActorType;
    actorId: string;
    projectId: string;
    actorAuthMethod: ActorAuthMethod;
    actorOrgId: string;
    actionProjectType?: ActionProjectType;
  }): Promise<{ permission: ProjectAbility; memberships: unknown[] }> => {
    // Admin bypass: if actorOrgId is set and actor is org admin, grant full access
    // (this is handled downstream by getOrgPermission checks)

    let combinedRules: RawRuleOf<ProjectAbility>[] = [];
    let memberships: unknown[] = [];

    if (actor === ActorType.USER) {
      const rows = await permissionDAL.getProjectPermission(actorId, projectId);
      memberships = rows;

      if (rows.length === 0) {
        // No membership — return no-access ability
        return { permission: buildProjectAbility([]), memberships: [] };
      }

      for (const row of rows) {
        if (row.isTemporary) {
          // Check if temporary access is still valid
          const now = new Date();
          const end = row.temporaryAccessEndTime;
          if (end && now > end) continue; // expired
        }

        const roleSlug = row.roleSlug;
        if (roleSlug === ProjectMembershipRole.Custom) {
          // Custom role — permissions stored as packed CASL rules
          if (row.permissions) {
            try {
              const packed = row.permissions as Parameters<typeof unpackRules>[0];
              const rules = unpackRules<RawRuleOf<ProjectAbility>>(packed);
              combinedRules = combinedRules.concat(rules);
            } catch (err) {
              logger.error(err, "Failed to unpack custom project role permissions");
            }
          }
        } else {
          combinedRules = combinedRules.concat(getDefaultProjectRules(roleSlug));
        }
      }
    } else if (actor === ActorType.IDENTITY) {
      const rows = await permissionDAL.getProjectIdentityPermission(actorId, projectId);
      memberships = rows;

      if (rows.length === 0) {
        return { permission: buildProjectAbility([]), memberships: [] };
      }

      for (const row of rows) {
        if (row.isTemporary) {
          const now = new Date();
          const end = row.temporaryAccessEndTime;
          if (end && now > end) continue;
        }

        const roleSlug = row.roleSlug;
        if (roleSlug === ProjectMembershipRole.Custom) {
          if (row.permissions) {
            try {
              const packed = row.permissions as Parameters<typeof unpackRules>[0];
              const rules = unpackRules<RawRuleOf<ProjectAbility>>(packed);
              combinedRules = combinedRules.concat(rules);
            } catch (err) {
              logger.error(err, "Failed to unpack custom project identity role permissions");
            }
          }
        } else {
          combinedRules = combinedRules.concat(getDefaultProjectRules(roleSlug));
        }
      }
    } else if (actor === ActorType.SERVICE) {
      // Service tokens get full access to their scoped project.
      // Fine-grained service token scope validation happens at the route level.
      const token = await serviceTokenDAL.findById(actorId);
      if (!token || token.projectId !== projectId) {
        return { permission: buildProjectAbility([]), memberships: [] };
      }
      // Grant member-level access for service tokens
      combinedRules = getDefaultProjectRules(ProjectMembershipRole.Admin);
    } else {
      return { permission: buildProjectAbility([]), memberships: [] };
    }

    return { permission: buildProjectAbility(combinedRules), memberships };
  };

  /**
   * Builds project permissions from an array of role slugs without DB lookup.
   * Used when the caller already knows which roles to evaluate.
   */
  const getProjectPermissionByRoles = async (
    projectRoles: string[],
    projectId?: string
  ): Promise<Array<{ permission: ProjectAbility; role: { name: string; slug: string; id: string | null } | null }>> => {
    const results: Array<{
      permission: ProjectAbility;
      role: { name: string; slug: string; id: string | null } | null;
    }> = [];

    for (const roleSlug of projectRoles) {
      const defaultRules = DEFAULT_PROJECT_ROLE_PERMISSIONS[roleSlug];
      if (defaultRules) {
        results.push({
          permission: buildProjectAbility(defaultRules as RawRuleOf<ProjectAbility>[]),
          role: { name: roleSlug, slug: roleSlug, id: null }
        });
        continue;
      }

      // Custom role: fetch from DB
      if (projectId) {
        try {
          const dbRole = await roleDAL.findOne({ slug: roleSlug, projectId });
          if (dbRole && dbRole.permissions) {
            const packed = dbRole.permissions as Parameters<typeof unpackRules>[0];
            const rules = unpackRules<RawRuleOf<ProjectAbility>>(packed);
            results.push({
              permission: buildProjectAbility(rules),
              role: { name: dbRole.name, slug: dbRole.slug, id: dbRole.id }
            });
            continue;
          }
        } catch (err) {
          logger.error(err, "Failed to fetch custom project role for permission by roles");
        }
      }

      results.push({ permission: buildProjectAbility([]), role: null });
    }

    return results;
  };

  /**
   * Returns bulk permissions for all users, identities, and groups in a project.
   * Used for access visibility features.
   */
  const getProjectPermissions = async (
    projectId: string,
    _actorOrgId: string
  ): Promise<{
    userPermissions: Array<{ permission: ProjectAbility; userId: string }>;
    identityPermissions: Array<{ permission: ProjectAbility; identityId: string }>;
    groupPermissions: Array<{ permission: ProjectAbility; groupId: string }>;
  }> => {
    // This is a best-effort implementation — returns empty arrays.
    // Full implementation would join all membership tables.
    // Routes that use this for access visibility are non-critical paths.
    logger.debug({ projectId }, "getProjectPermissions: returning empty stubs");
    return {
      userPermissions: [],
      identityPermissions: [],
      groupPermissions: []
    };
  };

  /**
   * Invalidates cached project permissions for a given project.
   * Currently a no-op since we don't use an external cache for permissions.
   */
  const invalidateProjectPermissionCache = async (_projectId: string): Promise<void> => {
    // No-op: permissions are computed fresh on each request from the DB.
  };

  // ------------------------------------------------------------------
  // Org permission
  // ------------------------------------------------------------------

  /**
   * Builds a CASL ability for the given actor in the given org.
   */
  const getOrgPermission = async (
    actorId: string,
    actor: ActorType,
    orgId: string,
    _actorAuthMethod: ActorAuthMethod,
    _actorOrgId: string
  ): Promise<{ permission: OrgAbility; membership: unknown }> => {
    let combinedRules: RawRuleOf<OrgAbility>[] = [];
    let membership: unknown = null;

    if (actor === ActorType.USER) {
      const rows = await permissionDAL.getOrgPermission(actorId, orgId);
      membership = rows[0] ?? null;

      if (rows.length === 0) {
        return { permission: buildOrgAbility([]), membership: null };
      }

      for (const row of rows) {
        const roleSlug = row.roleSlug;
        if (roleSlug === OrgMembershipRole.Custom) {
          if (row.permissions) {
            try {
              const packed = row.permissions as Parameters<typeof unpackRules>[0];
              const rules = unpackRules<RawRuleOf<OrgAbility>>(packed);
              combinedRules = combinedRules.concat(rules);
            } catch (err) {
              logger.error(err, "Failed to unpack custom org role permissions");
            }
          }
        } else {
          combinedRules = combinedRules.concat(getDefaultOrgRules(roleSlug));
        }
      }
    } else if (actor === ActorType.IDENTITY) {
      const rows = await permissionDAL.getOrgIdentityPermission(actorId, orgId);
      membership = rows[0] ?? null;

      if (rows.length === 0) {
        return { permission: buildOrgAbility([]), membership: null };
      }

      for (const row of rows) {
        const roleSlug = row.roleSlug;
        if (roleSlug === OrgMembershipRole.Custom) {
          if (row.permissions) {
            try {
              const packed = row.permissions as Parameters<typeof unpackRules>[0];
              const rules = unpackRules<RawRuleOf<OrgAbility>>(packed);
              combinedRules = combinedRules.concat(rules);
            } catch (err) {
              logger.error(err, "Failed to unpack custom org identity role permissions");
            }
          }
        } else {
          combinedRules = combinedRules.concat(getDefaultOrgRules(roleSlug));
        }
      }
    }

    return { permission: buildOrgAbility(combinedRules), membership };
  };

  /**
   * Builds org permissions from an array of role slugs without DB lookup.
   */
  const getOrgPermissionByRoles = async (
    roles: string[],
    orgId?: string
  ): Promise<Array<{ permission: OrgAbility; role: { name: string; slug: string; id: string | null } | null }>> => {
    const results: Array<{
      permission: OrgAbility;
      role: { name: string; slug: string; id: string | null } | null;
    }> = [];

    for (const roleSlug of roles) {
      const defaultRules = DEFAULT_ORG_ROLE_PERMISSIONS[roleSlug];
      if (defaultRules) {
        results.push({
          permission: buildOrgAbility(defaultRules as RawRuleOf<OrgAbility>[]),
          role: { name: roleSlug, slug: roleSlug, id: null }
        });
        continue;
      }

      // Custom role: fetch from DB
      if (orgId) {
        try {
          const dbRole = await roleDAL.findOne({ slug: roleSlug, orgId });
          if (dbRole && dbRole.permissions) {
            const packed = dbRole.permissions as Parameters<typeof unpackRules>[0];
            const rules = unpackRules<RawRuleOf<OrgAbility>>(packed);
            results.push({
              permission: buildOrgAbility(rules),
              role: { name: dbRole.name, slug: dbRole.slug, id: dbRole.id }
            });
            continue;
          }
        } catch (err) {
          logger.error(err, "Failed to fetch custom org role for permission by roles");
        }
      }

      results.push({ permission: buildOrgAbility([]), role: null });
    }

    return results;
  };

  return {
    getProjectPermission,
    getProjectPermissionByRoles,
    getProjectPermissions,
    invalidateProjectPermissionCache,
    getOrgPermission,
    getOrgPermissionByRoles
  };
};
