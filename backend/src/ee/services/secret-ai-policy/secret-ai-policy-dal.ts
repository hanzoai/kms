import { TDbClient } from "@app/db";
import { AiReadRequestStatus, TableName } from "@app/db/schemas";
import { ormify } from "@app/lib/knex";

export type TSecretAiPolicyDALFactory = ReturnType<typeof secretAiPolicyDALFactory>;

export const secretAiPolicyDALFactory = (db: TDbClient) => {
  const orm = ormify(db, TableName.SecretAiPolicy);

  const findByEnvAndPath = async (envId: string, secretPath: string) => {
    return db(TableName.SecretAiPolicy).where({ envId, secretPath }).first();
  };

  return { ...orm, findByEnvAndPath };
};

export type TAiSecretReadRequestDALFactory = ReturnType<typeof aiSecretReadRequestDALFactory>;

export const aiSecretReadRequestDALFactory = (db: TDbClient) => {
  const orm = ormify(db, TableName.AiSecretReadRequest);

  const expireOldRequests = async () => {
    return db(TableName.AiSecretReadRequest)
      .where("expiresAt", "<", new Date())
      .where("status", AiReadRequestStatus.Pending)
      .update({ status: AiReadRequestStatus.Expired });
  };

  const findPending = async (projectId: string, filters?: { identityId?: string; secretKey?: string }) => {
    const q = db(TableName.AiSecretReadRequest).where({ projectId, status: AiReadRequestStatus.Pending });
    if (filters?.identityId) q.where({ identityId: filters.identityId });
    if (filters?.secretKey) q.where({ secretKey: filters.secretKey });
    return q.orderBy("createdAt", "desc");
  };

  return { ...orm, expireOldRequests, findPending };
};
