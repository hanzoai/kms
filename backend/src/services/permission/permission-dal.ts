// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Permission DAL: raw DB queries for membership role lookups needed by the
// permission service. This intentionally keeps joins minimal — only the
// columns required to construct a CASL ability are fetched.

import { Knex } from "knex";

import { TDbClient } from "@app/db";
import { TableName } from "@app/db/schemas";
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
   * Joins project_memberships → membership_roles → roles.
   */
  const getProjectPermission = async (
    userId: string,
    projectId: string,
    tx?: Knex
  ): Promise<TProjectRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      const rows = await qb(TableName.ProjectMembership)
        .where(`${TableName.ProjectMembership}.userId`, userId)
        .where(`${TableName.ProjectMembership}.projectId`, projectId)
        .join(
          TableName.ProjectUserMembershipRole,
          `${TableName.ProjectUserMembershipRole}.projectMembershipId`,
          `${TableName.ProjectMembership}.id`
        )
        .leftJoin(TableName.ProjectRoles, function joinRoles() {
          this.on(
            `${TableName.ProjectRoles}.id`,
            `${TableName.ProjectUserMembershipRole}.customRoleId`
          ).andOn(db.raw(`${TableName.ProjectRoles}."projectId" = ?`, [projectId]));
        })
        .select(
          db.ref("role").withSchema(TableName.ProjectUserMembershipRole).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.ProjectRoles).as("permissions"),
          db.ref("isTemporary").withSchema(TableName.ProjectUserMembershipRole),
          db.ref("temporaryMode").withSchema(TableName.ProjectUserMembershipRole),
          db.ref("temporaryRange").withSchema(TableName.ProjectUserMembershipRole),
          db.ref("temporaryAccessStartTime").withSchema(TableName.ProjectUserMembershipRole),
          db.ref("temporaryAccessEndTime").withSchema(TableName.ProjectUserMembershipRole)
        );
      return rows as TProjectRolePermissionRow[];
    } catch (error) {
      throw new DatabaseError({ error, name: "GetProjectPermission" });
    }
  };

  /**
   * Returns all role permission rows for an identity in a given project.
   */
  const getProjectIdentityPermission = async (
    identityId: string,
    projectId: string,
    tx?: Knex
  ): Promise<TProjectRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      const rows = await qb(TableName.IdentityProjectMembership)
        .where(`${TableName.IdentityProjectMembership}.identityId`, identityId)
        .where(`${TableName.IdentityProjectMembership}.projectId`, projectId)
        .join(
          TableName.IdentityProjectMembershipRole,
          `${TableName.IdentityProjectMembershipRole}.projectMembershipId`,
          `${TableName.IdentityProjectMembership}.id`
        )
        .leftJoin(TableName.ProjectRoles, function joinRoles() {
          this.on(
            `${TableName.ProjectRoles}.id`,
            `${TableName.IdentityProjectMembershipRole}.customRoleId`
          ).andOn(db.raw(`${TableName.ProjectRoles}."projectId" = ?`, [projectId]));
        })
        .select(
          db.ref("role").withSchema(TableName.IdentityProjectMembershipRole).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.ProjectRoles).as("permissions"),
          db.ref("isTemporary").withSchema(TableName.IdentityProjectMembershipRole),
          db.ref("temporaryMode").withSchema(TableName.IdentityProjectMembershipRole),
          db.ref("temporaryRange").withSchema(TableName.IdentityProjectMembershipRole),
          db.ref("temporaryAccessStartTime").withSchema(TableName.IdentityProjectMembershipRole),
          db.ref("temporaryAccessEndTime").withSchema(TableName.IdentityProjectMembershipRole)
        );
      return rows as TProjectRolePermissionRow[];
    } catch (error) {
      throw new DatabaseError({ error, name: "GetProjectIdentityPermission" });
    }
  };

  // Org permission queries

  /**
   * Returns all role permission rows for a user in a given org.
   */
  const getOrgPermission = async (
    userId: string,
    orgId: string,
    tx?: Knex
  ): Promise<TOrgRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      const rows = await qb(TableName.OrgMembership)
        .where(`${TableName.OrgMembership}.userId`, userId)
        .where(`${TableName.OrgMembership}.orgId`, orgId)
        .where(`${TableName.OrgMembership}.isActive`, true)
        .leftJoin(TableName.OrgRoles, function joinOrgRoles() {
          this.on(
            `${TableName.OrgRoles}.id`,
            `${TableName.OrgMembership}.roleId`
          ).andOn(db.raw(`${TableName.OrgRoles}."orgId" = ?`, [orgId]));
        })
        .select(
          db.ref("role").withSchema(TableName.OrgMembership).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.OrgRoles).as("permissions")
        );
      return rows as TOrgRolePermissionRow[];
    } catch (error) {
      throw new DatabaseError({ error, name: "GetOrgPermission" });
    }
  };

  /**
   * Returns all role permission rows for an identity in a given org.
   */
  const getOrgIdentityPermission = async (
    identityId: string,
    orgId: string,
    tx?: Knex
  ): Promise<TOrgRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      const rows = await qb(TableName.IdentityOrgMembership)
        .where(`${TableName.IdentityOrgMembership}.identityId`, identityId)
        .where(`${TableName.IdentityOrgMembership}.orgId`, orgId)
        .leftJoin(TableName.OrgRoles, function joinOrgRoles() {
          this.on(
            `${TableName.OrgRoles}.id`,
            `${TableName.IdentityOrgMembership}.roleId`
          ).andOn(db.raw(`${TableName.OrgRoles}."orgId" = ?`, [orgId]));
        })
        .select(
          db.ref("role").withSchema(TableName.IdentityOrgMembership).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.OrgRoles).as("permissions")
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
