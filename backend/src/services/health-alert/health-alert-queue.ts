import { getConfig } from "@app/lib/config/env";
import { logger } from "@app/lib/logger";
import { QueueJobs, QueueName, TQueueServiceFactory } from "@app/queue";

type THealthAlertServiceFactoryDep = {
  queueService: TQueueServiceFactory;
  gatewayV2Service?: unknown;
  relayService?: unknown;
};

export type THealthAlertServiceFactory = ReturnType<typeof healthAlertServiceFactory>;

export const healthAlertServiceFactory = ({
  queueService,
  gatewayV2Service,
  relayService
}: THealthAlertServiceFactoryDep) => {
  const appCfg = getConfig();

  const init = async () => {
    if (appCfg.isSecondaryInstance) {
      return;
    }

    await queueService.stopRepeatableJob(
      QueueName.HealthAlert,
      QueueJobs.HealthAlert,
      { pattern: "*/5 * * * *", utc: true },
      QueueName.HealthAlert // job id
    );

    queueService.start(QueueName.HealthAlert, async () => {
      try {
        logger.info(`${QueueName.HealthAlert}: health check alert task started`);
        await gatewayV2Service.healthcheckNotify();
        await relayService.healthcheckNotify();
        logger.info(`${QueueName.HealthAlert}: health check alert task completed`);
      } catch (error) {
        logger.error(error, `${QueueName.HealthAlert}: health check alert failed`);
        throw error;
      }
    });

    await queueService.queue(QueueName.HealthAlert, QueueJobs.HealthAlert, undefined, {
      jobId: QueueJobs.HealthAlert,
      repeat: {
        pattern: "*/5 * * * *",
        key: QueueJobs.HealthAlert
      }
    });
  };

  return {
    init
  };
};
