// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Permission DAL: raw DB queries for membership role lookups needed by the
// permission service. After the 20260107 migration, old per-type membership
// tables were dropped. Now project_memberships and org_memberships are the
// single source of truth for both users and identities.

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
   * Uses the unified project_memberships table with optional role join.
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
        .leftJoin(TableName.ProjectRoles, function joinRoles() {
          this.on(
            `${TableName.ProjectRoles}.id`,
            `${TableName.ProjectMembership}.roleId`
          ).andOn(db.raw(`${TableName.ProjectRoles}."projectId" = ?`, [projectId]));
        })
        .select(
          db.ref("role").withSchema(TableName.ProjectMembership).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.ProjectRoles).as("permissions")
        );
      return rows as TProjectRolePermissionRow[];
    } catch (error) {
      throw new DatabaseError({ error, name: "GetProjectPermission" });
    }
  };

  /**
   * Returns all role permission rows for an identity in a given project.
   * After the membership unification, identities use the same project_memberships
   * table. If no membership exists, returns empty array (graceful degradation).
   */
  const getProjectIdentityPermission = async (
    identityId: string,
    projectId: string,
    tx?: Knex
  ): Promise<TProjectRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      // Identity permissions now go through the unified project_memberships table.
      // The identityId is stored in userId column for machine identities.
      const rows = await qb(TableName.ProjectMembership)
        .where(`${TableName.ProjectMembership}.userId`, identityId)
        .where(`${TableName.ProjectMembership}.projectId`, projectId)
        .leftJoin(TableName.ProjectRoles, function joinRoles() {
          this.on(
            `${TableName.ProjectRoles}.id`,
            `${TableName.ProjectMembership}.roleId`
          ).andOn(db.raw(`${TableName.ProjectRoles}."projectId" = ?`, [projectId]));
        })
        .select(
          db.ref("role").withSchema(TableName.ProjectMembership).as("roleSlug"),
          db.ref("permissions").withSchema(TableName.ProjectRoles).as("permissions")
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
   * After membership unification, identities use org_memberships directly.
   */
  const getOrgIdentityPermission = async (
    identityId: string,
    orgId: string,
    tx?: Knex
  ): Promise<TOrgRolePermissionRow[]> => {
    try {
      const qb = tx ?? db.replicaNode();
      // Identity org permissions now go through unified org_memberships table.
      const rows = await qb(TableName.OrgMembership)
        .where(`${TableName.OrgMembership}.userId`, identityId)
        .where(`${TableName.OrgMembership}.orgId`, orgId)
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
