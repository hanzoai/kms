import {
  AiReadRequestStatus,
  AiSecretPolicy,
  TAiSecretReadRequestsInsert,
  TAiSecretPolicy,
  TSecretAiPoliciesInsert
} from "@app/db/schemas";
import { ForbiddenRequestError, NotFoundError } from "@app/lib/errors";
import { TProjectEnvDALFactory } from "@app/services/project-env/project-env-dal";

import { TAiSecretReadRequestDALFactory, TSecretAiPolicyDALFactory } from "./secret-ai-policy-dal";

export type TSecretAiPolicyServiceFactory = ReturnType<typeof secretAiPolicyServiceFactory>;

type TDep = {
  secretAiPolicyDAL: TSecretAiPolicyDALFactory;
  aiSecretReadRequestDAL: TAiSecretReadRequestDALFactory;
  projectEnvDAL: Pick<TProjectEnvDALFactory, "findOne">;
};

export const secretAiPolicyServiceFactory = ({ secretAiPolicyDAL, aiSecretReadRequestDAL, projectEnvDAL }: TDep) => {
  // ── Policy CRUD ────────────────────────────────────────────────────────────

  const setPolicy = async ({
    projectId,
    environment,
    secretPath,
    policy,
    approverEmails,
    approvalTimeoutSeconds
  }: {
    projectId: string;
    environment: string;
    secretPath: string;
    policy: TAiSecretPolicy;
    approverEmails?: string[];
    approvalTimeoutSeconds?: number;
  }) => {
    const env = await projectEnvDAL.findOne({ projectId, slug: environment });
    if (!env) throw new NotFoundError({ message: `Environment '${environment}' not found in project` });

    const existing = await secretAiPolicyDAL.findByEnvAndPath(env.id, secretPath);

    const data: Partial<TSecretAiPoliciesInsert> = {
      policy,
      approverEmails: approverEmails ?? existing?.approverEmails ?? [],
      approvalTimeoutSeconds: approvalTimeoutSeconds ?? existing?.approvalTimeoutSeconds ?? 300
    };

    if (existing) {
      return secretAiPolicyDAL.updateById(existing.id, data);
    }

    return secretAiPolicyDAL.create({ envId: env.id, secretPath, ...data } as TSecretAiPoliciesInsert);
  };

  const getPolicy = async ({
    projectId,
    environment,
    secretPath
  }: {
    projectId: string;
    environment: string;
    secretPath: string;
  }) => {
    const env = await projectEnvDAL.findOne({ projectId, slug: environment });
    if (!env) return null;
    return secretAiPolicyDAL.findByEnvAndPath(env.id, secretPath);
  };

  // ── Read-request (approval queue) ─────────────────────────────────────────

  const requestSecretRead = async ({
    identityId,
    projectId,
    environment,
    secretKey,
    secretPath,
    agentType,
    tool,
    deviceId,
    reason
  }: {
    identityId: string;
    projectId: string;
    environment: string;
    secretKey: string;
    secretPath: string;
    agentType?: string;
    tool?: string;
    deviceId?: string;
    reason?: string;
  }) => {
    const env = await projectEnvDAL.findOne({ projectId, slug: environment });
    if (!env) throw new NotFoundError({ message: `Environment '${environment}' not found` });

    const policy = await secretAiPolicyDAL.findByEnvAndPath(env.id, secretPath);

    // default: auto-approve
    if (!policy || policy.policy === AiSecretPolicy.AutoApprove) {
      return { status: AiReadRequestStatus.Approved as const, requestId: null };
    }

    if (policy.policy === AiSecretPolicy.Blocked) {
      throw new ForbiddenRequestError({
        message: `AI access to secret '${secretKey}' is blocked by policy`
      });
    }

    // requires-approval — queue a request
    const timeoutSeconds = policy.approvalTimeoutSeconds ?? 300;
    const expiresAt = new Date(Date.now() + timeoutSeconds * 1000);

    const req = await aiSecretReadRequestDAL.create({
      policyId: policy.id,
      identityId,
      secretKey,
      secretPath,
      environment,
      projectId,
      agentType: agentType ?? null,
      tool: tool ?? null,
      deviceId: deviceId ?? null,
      reason: reason ?? null,
      status: AiReadRequestStatus.Pending,
      expiresAt
    } as TAiSecretReadRequestsInsert);

    return { status: AiReadRequestStatus.Pending as const, requestId: req.id };
  };

  const reviewRequest = async ({
    requestId,
    decision,
    reviewedBy
  }: {
    requestId: string;
    decision: "approved" | "denied";
    reviewedBy: string;
  }) => {
    const req = await aiSecretReadRequestDAL.findById(requestId);
    if (!req) throw new NotFoundError({ message: "AI read request not found" });
    if (req.status !== AiReadRequestStatus.Pending) {
      throw new ForbiddenRequestError({ message: `Request is already ${req.status}` });
    }
    if (req.expiresAt < new Date()) {
      await aiSecretReadRequestDAL.updateById(requestId, { status: AiReadRequestStatus.Expired });
      throw new ForbiddenRequestError({ message: "Request has expired" });
    }
    return aiSecretReadRequestDAL.updateById(requestId, { status: decision, reviewedBy });
  };

  const listRequests = async ({
    projectId,
    identityId,
    secretKey
  }: {
    projectId: string;
    identityId?: string;
    secretKey?: string;
  }) => {
    await aiSecretReadRequestDAL.expireOldRequests();
    return aiSecretReadRequestDAL.findPending(projectId, { identityId, secretKey });
  };

  const checkApproved = async (requestId: string) => {
    if (!requestId) return false;
    const req = await aiSecretReadRequestDAL.findById(requestId);
    if (!req) return false;
    if (req.expiresAt < new Date()) return false;
    return req.status === AiReadRequestStatus.Approved;
  };

  return { setPolicy, getPolicy, requestSecretRead, reviewRequest, listRequests, checkApproved };
};
