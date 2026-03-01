// MIT License
// Community edition: all features enabled, no license server required.
// Billing methods delegate to the Hanzo Commerce service when available.

import axios from "axios";

import { logger } from "@app/lib/logger";

export enum InstanceType {
  SelfHosted = "self-hosted",
  Cloud = "cloud"
}

const COMMERCE_DEFAULT_URL = "http://commerce.hanzo.svc:8001";

type TLicenseServiceFactoryConfig = {
  commerceUrl?: string;
};

export type TLicenseServiceFactory = ReturnType<typeof licenseServiceFactory>;

export const licenseServiceFactory = (config?: TLicenseServiceFactoryConfig) => {
  const commerceUrl =
    process.env.COMMERCE_SERVICE_URL ?? config?.commerceUrl ?? COMMERCE_DEFAULT_URL;

  const allFeaturesPlan = {
    slug: "enterprise",
    tier: -1,
    workspaceLimit: null as number | null,
    workspacesUsed: 0,
    memberLimit: null as number | null,
    membersUsed: 0,
    identityLimit: null as number | null,
    identitiesUsed: 0,
    environmentLimit: null as number | null,
    environmentsUsed: 0,
    secretVersioning: true,
    pitRecovery: true,
    rbac: true,
    customRateLimits: true,
    customAlerts: true,
    auditLogs: true,
    auditLogsRetentionDays: 365,
    samlSSO: true,
    hsm: true,
    oidcSSO: true,
    secretApproval: true,
    secretRotation: true,
    instanceUserManagement: true,
    externalKms: true,
    caCrl: true,
    sshHostGroups: true,
    pkiEst: true,
    kmip: true,
    gateway: true,
    ipAllowlisting: true,
    fips: true,
    eventSubscriptions: true,
    secretAccessInsights: true
  };

  const getPlan = async (_orgId?: string) => allFeaturesPlan;

  const getOrgPlan = async (_orgId: string) => allFeaturesPlan;

  const getInstancePlan = () => allFeaturesPlan;

  const updateSubscriptionOrgMemberCount = async (_orgId: string) => {};

  const refreshPlan = async (_orgId: string) => allFeaturesPlan;

  const getPlanByOrgId = async (_orgId: string) => allFeaturesPlan;

  const onPremFeatures = {
    ...allFeaturesPlan,
    has: (_feature: string) => true
  };

  const getOrgBillingInfo = async (orgId: string) => {
    const nullDefaults = {
      currentPeriodEnd: null as number | null,
      currentPeriodStart: null as number | null,
      amount: null as number | null,
      interval: null as string | null,
      intervalCount: null as number | null,
      quantity: null as number | null
    };

    try {
      const { data } = await axios.get(`${commerceUrl}/api/v1/billing/org/${orgId}`, {
        timeout: 5000
      });
      return { ...nullDefaults, ...data };
    } catch (err) {
      logger.warn({ orgId, err }, "license: getOrgBillingInfo Commerce unreachable — returning nulls");
      return nullDefaults;
    }
  };

  const getOrgTaxIds = async (_orgId: string) => [] as unknown[];

  const addOrgTaxId = async (_orgId: string, _type: string, _value: string) => {};

  const delOrgTaxId = async (_orgId: string, _taxId: string) => {};

  const getOrgTrialUrl = async (_orgId: string, _successUrl: string) => "";

  const requestEnterpriseTrial = async (_orgId: string, _name: string, _email: string) => {};

  const updateOrgBillingDetails = async (_data: unknown) => {};

  const startFreeTrial = async (orgId: string) => {
    try {
      await axios.post(`${commerceUrl}/api/v1/billing/trial`, { orgId }, { timeout: 5000 });
    } catch (err) {
      logger.warn({ orgId, err }, "license: startFreeTrial Commerce unreachable — skipping");
    }
  };

  const generateOrgCustomerPortalSession = async (orgId: string) => {
    try {
      const { data } = await axios.post(
        `${commerceUrl}/api/v1/billing/portal-session`,
        { orgId },
        { timeout: 5000 }
      );
      return { url: (data as { url?: string }).url ?? "" };
    } catch (err) {
      logger.warn({ orgId, err }, "license: generateOrgCustomerPortalSession Commerce unreachable — returning empty URL");
      return { url: "" };
    }
  };

  const getOrgPlansTable = async (orgId: string) => {
    try {
      const { data } = await axios.get(`${commerceUrl}/api/v1/plans`, {
        params: { orgId },
        timeout: 5000
      });
      return Array.isArray(data) ? data : [];
    } catch (err) {
      logger.warn({ orgId, err }, "license: getOrgPlansTable Commerce unreachable — returning empty list");
      return [] as unknown[];
    }
  };

  const getOrganizationRateLimit = async (_orgId: string) => ({
    readLimit: 60,
    writeLimit: 200,
    secretsLimit: 40,
    readSecretLimit: 2000,
    credsLimit: 300
  });

  const invalidateCache = async (_orgId: string) => {};

  const init = async () => {};

  const initializeBackgroundSync = async () => null as null;

  const getInstanceType = () => InstanceType.SelfHosted;

  const generateOrgCustomerId = async (_orgId: string) => "";
  const removeOrgCustomer = async (_orgId: string) => {};
  const getCustomerId = async (_orgId: string) => null as string | null;
  const getLicenseId = async (_orgId: string) => null as string | null;
  const invalidateGetPlan = async (_orgId: string) => {};

  return {
    getPlan,
    getOrgPlan,
    getInstancePlan,
    updateSubscriptionOrgMemberCount,
    refreshPlan,
    getPlanByOrgId,
    onPremFeatures,
    getOrgBillingInfo,
    getOrgTaxIds,
    addOrgTaxId,
    delOrgTaxId,
    getOrgTrialUrl,
    requestEnterpriseTrial,
    updateOrgBillingDetails,
    startFreeTrial,
    generateOrgCustomerPortalSession,
    getOrgPlansTable,
    getOrganizationRateLimit,
    invalidateCache,
    init,
    initializeBackgroundSync,
    getInstanceType,
    generateOrgCustomerId,
    removeOrgCustomer,
    getCustomerId,
    getLicenseId,
    invalidateGetPlan
  };
};
