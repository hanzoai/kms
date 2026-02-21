import { TKeyStoreFactory } from "@app/keystore/keystore";
import { logger } from "@app/lib/logger";
import { QueueJobs, QueueName, TQueueServiceFactory } from "@app/queue";

import { CacheType } from "./super-admin-types";

export type TInvalidateCacheQueueFactoryDep = {
  queueService: TQueueServiceFactory;

  keyStore: Pick<TKeyStoreFactory, "deleteItems" | "setItemWithExpiry" | "deleteItem">;
};

export type TInvalidateCacheQueueFactory = ReturnType<typeof invalidateCacheQueueFactory>;

export const invalidateCacheQueueFactory = ({ queueService, keyStore }: TInvalidateCacheQueueFactoryDep) => {
  const startInvalidate = async (dto: {
    data: {
      type: CacheType;
    };
  }) => {
    await queueService.queue(QueueName.InvalidateCache, QueueJobs.InvalidateCache, dto, {
      removeOnComplete: true,
      removeOnFail: true,
      jobId: `invalidate-cache-${dto.data.type}`
    });
  };

  queueService.start(QueueName.InvalidateCache, async (job) => {
    try {
      const {
        data: { type }
      } = job.data;

      // WARNING: This is an instance-wide operation that affects ALL organizations.
      // The secret-manager cache keys are keyed by projectId, not orgId, so this
      // wipes cached secrets for every project across every tenant. This is by design
      // as a super-admin recovery tool, but should be used sparingly. Only super-admins
      // can trigger this operation (enforced by the admin router).
      logger.info({ type }, "Instance-wide cache invalidation started (affects all organizations)");

      await keyStore.setItemWithExpiry("invalidating-cache", 1800, "true"); // 30 minutes max (in case the job somehow silently fails)

      if (type === CacheType.ALL || type === CacheType.SECRETS)
        await keyStore.deleteItems({ pattern: "secret-manager:*" });

      await keyStore.deleteItem("invalidating-cache");
      logger.info({ type }, "Instance-wide cache invalidation completed");
    } catch (err) {
      logger.error(err, "Failed to invalidate cache");
      await keyStore.deleteItem("invalidating-cache");
    }
  });

  return {
    startInvalidate
  };
};
