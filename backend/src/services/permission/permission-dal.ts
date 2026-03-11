// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Permission DAL: raw DB queries for membership role lookups needed by the
// permission service. Uses the unified Membership + MembershipRole + Role
// tables introduced in 20251005152640_simplify-membership.

import { Knex } from "knex";

import { TDbClient } from "@app/db";
import { AccessScope, TableName } from "@app/db/schemas";
import { DatabaseError } from "@app/lib/errors";

export type TPermissionDALFactory = ReturnType<typeof permissionDALFactory>;

// Shape of a resolved role row coming from the DB join.
export type TProjectRolePermissionRow = {
  roleSlug: string;
  permissions: unknown; // packed CASL rules JSON
  isTemporary?: boolean | null;
  temporaryMode?: string | null;
  temporaryRange?: string | null;
  temporaryAccessStartTime?: Date | null;
  temporaryAccessEndTime?: Date | null;
};

export type TOrgRolePermissionRow = {
  roleSlug: string;
  permissions: unknown;
};

export const permissionDALFactory = (db: TDbClient) => {
  // Project permission queries

  /**
   * Returns all role permission rows for a user in a given project.
   * Queries: memberships → membership_roles → roles (custom only).
   */
  const getProjectPermission = async (
    userId: string,
    projectId: string,
    tx?: Knex
  ): Promise<TProjectRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      const rows = await qb(TableName.Membership)
        .where(`${TableName.Membership}.actorUserId`, userId)
        .where(`${TableName.Membership}.scopeProjectId`, projectId)
        .where(`${TableName.Membership}.scope`, AccessScope.Project)
        .join(
          TableName.MembershipRole,
          `${TableName.MembershipRole}.membershipId`,
          `${TableName.Membership}.id`
        )
        .leftJoin(TableName.Role, `${TableName.MembershipRole}.customRoleId`, `${TableName.Role}.id`)
        .select(
          db.ref("role").withSchema(TableName.MembershipRole).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.Role).as("permissions"),
          db.ref("isTemporary").withSchema(TableName.MembershipRole),
          db.ref("temporaryMode").withSchema(TableName.MembershipRole),
          db.ref("temporaryRange").withSchema(TableName.MembershipRole),
          db.ref("temporaryAccessStartTime").withSchema(TableName.MembershipRole),
          db.ref("temporaryAccessEndTime").withSchema(TableName.MembershipRole)
        );
      return rows as TProjectRolePermissionRow[];
    } catch (error) {
      throw new DatabaseError({ error, name: "GetProjectPermission" });
    }
  };

  /**
   * Returns all role permission rows for an identity in a given project.
   * Queries: memberships (actorIdentityId) → membership_roles → roles (custom only).
   */
  const getProjectIdentityPermission = async (
    identityId: string,
    projectId: string,
    tx?: Knex
  ): Promise<TProjectRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      const rows = await qb(TableName.Membership)
        .where(`${TableName.Membership}.actorIdentityId`, identityId)
        .where(`${TableName.Membership}.scopeProjectId`, projectId)
        .where(`${TableName.Membership}.scope`, AccessScope.Project)
        .join(
          TableName.MembershipRole,
          `${TableName.MembershipRole}.membershipId`,
          `${TableName.Membership}.id`
        )
        .leftJoin(TableName.Role, `${TableName.MembershipRole}.customRoleId`, `${TableName.Role}.id`)
        .select(
          db.ref("role").withSchema(TableName.MembershipRole).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.Role).as("permissions"),
          db.ref("isTemporary").withSchema(TableName.MembershipRole),
          db.ref("temporaryMode").withSchema(TableName.MembershipRole),
          db.ref("temporaryRange").withSchema(TableName.MembershipRole),
          db.ref("temporaryAccessStartTime").withSchema(TableName.MembershipRole),
          db.ref("temporaryAccessEndTime").withSchema(TableName.MembershipRole)
        );
      return rows as TProjectRolePermissionRow[];
    } catch (error) {
      throw new DatabaseError({ error, name: "GetProjectIdentityPermission" });
    }
  };

  // Org permission queries

  /**
   * Returns all role permission rows for a user in a given org.
   * Queries: memberships (actorUserId, scope=organization) → membership_roles → roles.
   */
  const getOrgPermission = async (
    userId: string,
    orgId: string,
    tx?: Knex
  ): Promise<TOrgRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      const rows = await qb(TableName.Membership)
        .where(`${TableName.Membership}.actorUserId`, userId)
        .where(`${TableName.Membership}.scopeOrgId`, orgId)
        .where(`${TableName.Membership}.scope`, AccessScope.Organization)
        .join(
          TableName.MembershipRole,
          `${TableName.MembershipRole}.membershipId`,
          `${TableName.Membership}.id`
        )
        .leftJoin(TableName.Role, `${TableName.MembershipRole}.customRoleId`, `${TableName.Role}.id`)
        .select(
          db.ref("role").withSchema(TableName.MembershipRole).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.Role).as("permissions")
        );
      return rows as TOrgRolePermissionRow[];
    } catch (error) {
      throw new DatabaseError({ error, name: "GetOrgPermission" });
    }
  };

  /**
   * Returns all role permission rows for an identity in a given org.
   * Queries: memberships (actorIdentityId, scope=organization) → membership_roles → roles.
   */
  const getOrgIdentityPermission = async (
    identityId: string,
    orgId: string,
    tx?: Knex
  ): Promise<TOrgRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      const rows = await qb(TableName.Membership)
        .where(`${TableName.Membership}.actorIdentityId`, identityId)
        .where(`${TableName.Membership}.scopeOrgId`, orgId)
        .where(`${TableName.Membership}.scope`, AccessScope.Organization)
        .join(
          TableName.MembershipRole,
          `${TableName.MembershipRole}.membershipId`,
          `${TableName.Membership}.id`
        )
        .leftJoin(TableName.Role, `${TableName.MembershipRole}.customRoleId`, `${TableName.Role}.id`)
        .select(
          db.ref("role").withSchema(TableName.MembershipRole).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.Role).as("permissions")
        );
      return rows as TOrgRolePermissionRow[];
    } catch (error) {
      throw new DatabaseError({ error, name: "GetOrgIdentityPermission" });
    }
  };

  return {
    getProjectPermission,
    getProjectIdentityPermission,
    getOrgPermission,
    getOrgIdentityPermission
  };
};
