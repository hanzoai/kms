// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT

import { Knex } from "knex";

import { TDbClient } from "@app/db";
import { TableName, TAuditLogs, TAuditLogsInsert } from "@app/db/schemas";
import { DatabaseError } from "@app/lib/errors";
import { ormify } from "@app/lib/knex";

export type TAuditLogDALFactory = ReturnType<typeof auditLogDALFactory>;

export const auditLogDALFactory = (db: TDbClient) => {
  const orm = ormify(db, TableName.AuditLog);

  const insertAuditLog = async (data: TAuditLogsInsert, tx?: Knex): Promise<TAuditLogs> => {
    try {
      const [row] = await (tx ?? db)(TableName.AuditLog).insert(data).returning("*");
      return row as TAuditLogs;
    } catch (error) {
      throw new DatabaseError({ error, name: "InsertAuditLog" });
    }
  };

  const pruneExpired = async (tx?: Knex): Promise<number> => {
    try {
      const deleted = await (tx ?? db)(TableName.AuditLog)
        .where("expiresAt", "<", new Date())
        .whereNotNull("expiresAt")
        .delete();
      return deleted as number;
    } catch (error) {
      throw new DatabaseError({ error, name: "PruneExpiredAuditLogs" });
    }
  };

  return {
    ...orm,
    insertAuditLog,
    pruneExpired
  };
};
