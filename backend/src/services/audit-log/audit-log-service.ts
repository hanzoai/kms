// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Audit log service: thin facade around async queue-based persistence.
// Route handlers call createAuditLog; the queue worker does the DB write.
//
// Design: the factory accepts optional queue deps. When called with no args
// (as in the current routes bootstrap), createAuditLog is a best-effort
// no-op that logs the event but does not persist — actual persistence
// requires wiring the auditLogQueue (TAuditLogQueueServiceFactory) in.

import { logger } from "@app/lib/logger";

import { TAuditLogQueueServiceFactory } from "./audit-log-queue";
import { TCreateAuditLogDTO } from "./audit-log-types";

type TAuditLogServiceFactoryDep = {
  auditLogQueue?: TAuditLogQueueServiceFactory;
};

export type TAuditLogServiceFactory = ReturnType<typeof auditLogServiceFactory>;

export const auditLogServiceFactory = (deps?: TAuditLogServiceFactoryDep) => {
  const createAuditLog = async (dto: TCreateAuditLogDTO): Promise<void> => {
    try {
      if (deps?.auditLogQueue) {
        await deps.auditLogQueue.pushToQueue(dto);
      } else {
        // Queue not wired — log event at debug level so it is not silently lost.
        logger.debug(
          { event: dto.event.type, actor: dto.actor.type, orgId: dto.orgId, projectId: dto.projectId },
          "audit-log [no-queue]: event not persisted"
        );
      }
    } catch (err) {
      // Audit log failures must never propagate to the caller.
      logger.error(err, "audit-log createAuditLog failed");
    }
  };

  return { createAuditLog };
};
