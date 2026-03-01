import { FastifyInstance, RawReplyDefaultExpression, RawRequestDefaultExpression, RawServerDefault } from "fastify";

import { CustomLogger } from "@app/lib/logger/logger";
import { ZodTypeProvider } from "@app/server/plugins/fastify-zod";
import { TKmsRootConfigDALFactory } from "@app/services/kms/kms-root-config-dal";
import { TSuperAdminDALFactory } from "@app/services/super-admin/super-admin-dal";
import { THsmServiceFactory } from "@app/services/hsm/hsm-service";

declare global {
  type FastifyZodProvider = FastifyInstance<
    RawServerDefault,
    RawRequestDefaultExpression<RawServerDefault>,
    RawReplyDefaultExpression<RawServerDefault>,
    Readonly<CustomLogger>,
    ZodTypeProvider
  >;

  // used only for testing
  const testServer: FastifyZodProvider;
  const testSuperAdminDAL: TSuperAdminDALFactory;
  const testKmsRootConfigDAL: TKmsRootConfigDALFactory;
  const testHsmService: THsmServiceFactory;
  const jwtAuthToken: string;
}
