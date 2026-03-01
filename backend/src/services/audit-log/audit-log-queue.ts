// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Async queue-backed audit log writer.
// Uses BullMQ (via queueService) for reliable write-through to PostgreSQL,
// and optionally ClickHouse when a client is configured.

import type { ClickHouseClient } from "@clickhouse/client";

import { getConfig } from "@app/lib/config/env";
import { logger } from "@app/lib/logger";
import { QueueJobs, QueueName, TQueueServiceFactory } from "@app/queue";
import { TProjectDALFactory } from "@app/services/project/project-dal";
import { TLicenseServiceFactory } from "@app/services/license/license-service";

import { clickhouseAuditLogDALFactory } from "./audit-log-clickhouse-dal";
import { TAuditLogDALFactory } from "./audit-log-dal";
import { TCreateAuditLogDTO } from "./audit-log-types";

type TAuditLogQueueServiceFactoryDep = {
  auditLogDAL: TAuditLogDALFactory;
  queueService: TQueueServiceFactory;
  projectDAL: Pick<TProjectDALFactory, "findById">;
  licenseService: TLicenseServiceFactory;
  clickhouseClient?: ClickHouseClient | null;
};

export type TAuditLogQueueServiceFactory = ReturnType<typeof auditLogQueueServiceFactory> extends Promise<infer T>
  ? T
  : never;

export const auditLogQueueServiceFactory = async ({
  auditLogDAL,
  queueService,
  projectDAL,
  licenseService,
  clickhouseClient
}: TAuditLogQueueServiceFactoryDep) => {
  const appCfg = getConfig();

  // Optional ClickHouse DAL — only instantiated when a client is present.
  const clickhouseDAL =
    clickhouseClient
      ? clickhouseAuditLogDALFactory(clickhouseClient, {} as never, appCfg.CLICKHOUSE_AUDIT_LOG_TABLE_NAME)
      : null;

  queueService.start(QueueName.AuditLog, async (job) => {
    const dto = job.data as TCreateAuditLogDTO;

    try {
      // Determine retention from license plan
      let retentionDays = 30;
      try {
        const orgId = dto.orgId ?? (dto.projectId ? (await projectDAL.findById(dto.projectId))?.orgId : undefined);
        if (orgId) {
          const plan = await licenseService.getPlan(orgId);
          retentionDays = plan.auditLogsRetentionDays ?? 30;
        }
      } catch {
        // default retention on any error
      }

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + retentionDays);

      const row = await auditLogDAL.insertAuditLog({
        actor: dto.actor.type,
        actorMetadata: dto.actor.metadata,
        eventType: dto.event.type,
        eventMetadata: dto.event.metadata ?? null,
        orgId: dto.orgId,
        projectId: dto.projectId,
        ipAddress: dto.ipAddress,
        userAgent: dto.userAgent,
        userAgentType: dto.userAgentType,
        expiresAt
      });

      if (clickhouseDAL) {
        await clickhouseDAL.insertAuditLog({
          ...dto,
          id: row.id,
          createdAt: row.createdAt
        });
      }
    } catch (err) {
      logger.error(err, "audit log write failed");
      throw err; // BullMQ will retry
    }
  });

  const pushToQueue = async (dto: TCreateAuditLogDTO): Promise<void> => {
    await queueService.queue(QueueName.AuditLog, QueueJobs.AuditLog, dto, {
      jobId: `audit-log-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      removeOnComplete: { count: 0 },
      removeOnFail: { count: 5000 }
    });
  };

  return { pushToQueue };
};
