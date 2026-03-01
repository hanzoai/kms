// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// ClickHouse audit log DAL - optional secondary write path.
// When no ClickHouse client is provided the factory is not created and writes
// go only to PostgreSQL.

import type { ClickHouseClient } from "@clickhouse/client";
import { Knex } from "knex";

import { logger } from "@app/lib/logger";

import { TCreateAuditLogDTO } from "./audit-log-types";

export type TClickhouseAuditLogDALFactory = ReturnType<typeof clickhouseAuditLogDALFactory>;

export const clickhouseAuditLogDALFactory = (
  client: ClickHouseClient,
  _db: Knex,
  tableName = "audit_logs_v2"
) => {
  const insertAuditLog = async (dto: TCreateAuditLogDTO & { id: string; createdAt: Date }): Promise<void> => {
    try {
      await client.insert({
        table: tableName,
        values: [
          {
            id: dto.id,
            actor: dto.actor.type,
            actor_metadata: JSON.stringify(dto.actor.metadata),
            event_type: dto.event.type,
            event_metadata: dto.event.metadata ? JSON.stringify(dto.event.metadata) : null,
            org_id: dto.orgId ?? null,
            project_id: dto.projectId ?? null,
            ip_address: dto.ipAddress ?? null,
            user_agent: dto.userAgent ?? null,
            user_agent_type: dto.userAgentType ?? null,
            created_at: dto.createdAt.toISOString()
          }
        ],
        format: "JSONEachRow"
      });
    } catch (error) {
      // ClickHouse failures are non-fatal: the PG write is the source of truth.
      logger.error(error, "clickhouse audit log insert failed");
    }
  };

  return { insertAuditLog };
};
