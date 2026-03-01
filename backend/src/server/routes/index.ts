import { registerBddNockRouter } from "@bdd_routes/bdd-nock-router";
import type { ClickHouseClient } from "@clickhouse/client";
import { CronJob } from "cron";
import { Knex } from "knex";
import { monitorEventLoopDelay } from "perf_hooks";
import { z } from "zod";

import {
  aiSecretReadRequestDALFactory,
  secretAiPolicyDALFactory
} from "@app/services/secret-ai-policy/secret-ai-policy-dal";
import { secretAiPolicyServiceFactory } from "@app/services/secret-ai-policy/secret-ai-policy-service";
import { clickhouseAuditLogDALFactory } from "@app/services/audit-log/audit-log-clickhouse-dal";
import { auditLogDALFactory } from "@app/services/audit-log/audit-log-dal";
import { auditLogQueueServiceFactory } from "@app/services/audit-log/audit-log-queue";
import { auditLogServiceFactory } from "@app/services/audit-log/audit-log-service";
import { permissionDALFactory } from "@app/services/permission/permission-dal";
import { permissionServiceFactory } from "@app/services/permission/permission-service";
import { keyValueStoreDALFactory } from "@app/keystore/key-value-store-dal";
import { TKeyStoreFactory } from "@app/keystore/keystore";
import { getConfig, TEnvConfig } from "@app/lib/config/env";
import { crypto } from "@app/lib/crypto/cryptography";
import { BadRequestError } from "@app/lib/errors";
import { logger } from "@app/lib/logger";
import { TQueueServiceFactory } from "@app/queue";
import { queueJobsDALFactory } from "@app/queue/queue-jobs-dal";
import { readLimit } from "@app/server/config/rateLimiter";
import { registerSecretScanningV2Webhooks } from "@app/server/plugins/secret-scanner-v2";
import { accessTokenQueueServiceFactory } from "@app/services/access-token-queue/access-token-queue";
import { accountRecoveryServiceFactory } from "@app/services/account-recovery/account-recovery-service";
import { additionalPrivilegeDALFactory } from "@app/services/additional-privilege/additional-privilege-dal";
import { additionalPrivilegeServiceFactory } from "@app/services/additional-privilege/additional-privilege-service";
import { apiKeyDALFactory } from "@app/services/api-key/api-key-dal";
import { apiKeyServiceFactory } from "@app/services/api-key/api-key-service";
import { appConnectionDALFactory } from "@app/services/app-connection/app-connection-dal";
import { appConnectionServiceFactory } from "@app/services/app-connection/app-connection-service";
import {
  approvalPolicyDALFactory,
  approvalPolicyStepApproversDALFactory,
  approvalPolicyStepsDALFactory
} from "@app/services/approval-policy/approval-policy-dal";
import { approvalPolicyServiceFactory } from "@app/services/approval-policy/approval-policy-service";
import {
  approvalRequestApprovalsDALFactory,
  approvalRequestDALFactory,
  approvalRequestGrantsDALFactory,
  approvalRequestStepEligibleApproversDALFactory,
  approvalRequestStepsDALFactory
} from "@app/services/approval-policy/approval-request-dal";
import { authDALFactory } from "@app/services/auth/auth-dal";
import { authLoginServiceFactory } from "@app/services/auth/auth-login-service";
import { authPaswordServiceFactory } from "@app/services/auth/auth-password-service";
import { authSignupServiceFactory } from "@app/services/auth/auth-signup-service";
import { tokenDALFactory } from "@app/services/auth-token/auth-token-dal";
import { tokenServiceFactory } from "@app/services/auth-token/auth-token-service";
import { certificateBodyDALFactory } from "@app/services/certificate/certificate-body-dal";
import { certificateDALFactory } from "@app/services/certificate/certificate-dal";
import { certificateSecretDALFactory } from "@app/services/certificate/certificate-secret-dal";
import { certificateServiceFactory } from "@app/services/certificate/certificate-service";
import { certificateAuthorityCertDALFactory } from "@app/services/certificate-authority/certificate-authority-cert-dal";
import { certificateAuthorityDALFactory } from "@app/services/certificate-authority/certificate-authority-dal";
import { certificateAuthorityQueueFactory } from "@app/services/certificate-authority/certificate-authority-queue";
import { certificateAuthoritySecretDALFactory } from "@app/services/certificate-authority/certificate-authority-secret-dal";
import { certificateAuthorityServiceFactory } from "@app/services/certificate-authority/certificate-authority-service";
import { certificateIssuanceQueueFactory } from "@app/services/certificate-authority/certificate-issuance-queue";
import { externalCertificateAuthorityDALFactory } from "@app/services/certificate-authority/external-certificate-authority-dal";
import { internalCertificateAuthorityDALFactory } from "@app/services/certificate-authority/internal/internal-certificate-authority-dal";
import { InternalCertificateAuthorityFns } from "@app/services/certificate-authority/internal/internal-certificate-authority-fns";
import { internalCertificateAuthorityServiceFactory } from "@app/services/certificate-authority/internal/internal-certificate-authority-service";
import { certificateEstV3ServiceFactory } from "@app/services/certificate-est-v3/certificate-est-v3-service";
import { certificatePolicyDALFactory } from "@app/services/certificate-policy/certificate-policy-dal";
import { certificatePolicyServiceFactory } from "@app/services/certificate-policy/certificate-policy-service";
import { certificateProfileDALFactory } from "@app/services/certificate-profile/certificate-profile-dal";
import { certificateProfileServiceFactory } from "@app/services/certificate-profile/certificate-profile-service";
import { certificateRequestDALFactory } from "@app/services/certificate-request/certificate-request-dal";
import { certificateRequestServiceFactory } from "@app/services/certificate-request/certificate-request-service";
import { certificateSyncDALFactory } from "@app/services/certificate-sync/certificate-sync-dal";
import { certificateTemplateDALFactory } from "@app/services/certificate-template/certificate-template-dal";
import { certificateTemplateEstConfigDALFactory } from "@app/services/certificate-template/certificate-template-est-config-dal";
import { certificateTemplateServiceFactory } from "@app/services/certificate-template/certificate-template-service";
import { certificateApprovalServiceFactory } from "@app/services/certificate-v3/certificate-approval-fns";
import { certificateV3QueueServiceFactory } from "@app/services/certificate-v3/certificate-v3-queue";
import { certificateV3ServiceFactory } from "@app/services/certificate-v3/certificate-v3-service";
import { cmekServiceFactory } from "@app/services/cmek/cmek-service";
import { convertorServiceFactory } from "@app/services/convertor/convertor-service";
import { acmeEnrollmentConfigDALFactory } from "@app/services/enrollment-config/acme-enrollment-config-dal";
import { apiEnrollmentConfigDALFactory } from "@app/services/enrollment-config/api-enrollment-config-dal";
import { estEnrollmentConfigDALFactory } from "@app/services/enrollment-config/est-enrollment-config-dal";
import { externalGroupOrgRoleMappingDALFactory } from "@app/services/external-group-org-role-mapping/external-group-org-role-mapping-dal";
import { externalGroupOrgRoleMappingServiceFactory } from "@app/services/external-group-org-role-mapping/external-group-org-role-mapping-service";
import { externalMigrationQueueFactory } from "@app/services/external-migration/external-migration-queue";
import { externalMigrationServiceFactory } from "@app/services/external-migration/external-migration-service";
import { vaultExternalMigrationConfigDALFactory } from "@app/services/external-migration/vault-external-migration-config-dal";
import { folderCheckpointDALFactory } from "@app/services/folder-checkpoint/folder-checkpoint-dal";
import { folderCheckpointResourcesDALFactory } from "@app/services/folder-checkpoint-resources/folder-checkpoint-resources-dal";
import { folderCommitDALFactory } from "@app/services/folder-commit/folder-commit-dal";
import { folderCommitQueueServiceFactory } from "@app/services/folder-commit/folder-commit-queue";
import { folderCommitServiceFactory } from "@app/services/folder-commit/folder-commit-service";
import { folderCommitChangesDALFactory } from "@app/services/folder-commit-changes/folder-commit-changes-dal";
import { folderTreeCheckpointDALFactory } from "@app/services/folder-tree-checkpoint/folder-tree-checkpoint-dal";
import { folderTreeCheckpointResourcesDALFactory } from "@app/services/folder-tree-checkpoint-resources/folder-tree-checkpoint-resources-dal";
import { groupProjectDALFactory } from "@app/services/group-project/group-project-dal";
import { groupProjectServiceFactory } from "@app/services/group-project/group-project-service";
import { healthAlertServiceFactory } from "@app/services/health-alert/health-alert-queue";
import { identityDALFactory } from "@app/services/identity/identity-dal";
import { identityMetadataDALFactory } from "@app/services/identity/identity-metadata-dal";
import { identityOrgDALFactory } from "@app/services/identity/identity-org-dal";
import { identityServiceFactory } from "@app/services/identity/identity-service";
import { identityAccessTokenDALFactory } from "@app/services/identity-access-token/identity-access-token-dal";
import { identityAccessTokenServiceFactory } from "@app/services/identity-access-token/identity-access-token-service";
import { identityAliCloudAuthDALFactory } from "@app/services/identity-alicloud-auth/identity-alicloud-auth-dal";
import { identityAliCloudAuthServiceFactory } from "@app/services/identity-alicloud-auth/identity-alicloud-auth-service";
import { identityAwsAuthDALFactory } from "@app/services/identity-aws-auth/identity-aws-auth-dal";
import { identityAwsAuthServiceFactory } from "@app/services/identity-aws-auth/identity-aws-auth-service";
import { identityAzureAuthDALFactory } from "@app/services/identity-azure-auth/identity-azure-auth-dal";
import { identityAzureAuthServiceFactory } from "@app/services/identity-azure-auth/identity-azure-auth-service";
import { identityGcpAuthDALFactory } from "@app/services/identity-gcp-auth/identity-gcp-auth-dal";
import { identityGcpAuthServiceFactory } from "@app/services/identity-gcp-auth/identity-gcp-auth-service";
import { identityJwtAuthDALFactory } from "@app/services/identity-jwt-auth/identity-jwt-auth-dal";
import { identityJwtAuthServiceFactory } from "@app/services/identity-jwt-auth/identity-jwt-auth-service";
import { identityKubernetesAuthDALFactory } from "@app/services/identity-kubernetes-auth/identity-kubernetes-auth-dal";
import { identityKubernetesAuthServiceFactory } from "@app/services/identity-kubernetes-auth/identity-kubernetes-auth-service";
import { identityLdapAuthDALFactory } from "@app/services/identity-ldap-auth/identity-ldap-auth-dal";
import { identityLdapAuthServiceFactory } from "@app/services/identity-ldap-auth/identity-ldap-auth-service";
import { identityOciAuthDALFactory } from "@app/services/identity-oci-auth/identity-oci-auth-dal";
import { identityOciAuthServiceFactory } from "@app/services/identity-oci-auth/identity-oci-auth-service";
import { identityOidcAuthDALFactory } from "@app/services/identity-oidc-auth/identity-oidc-auth-dal";
import { identityOidcAuthServiceFactory } from "@app/services/identity-oidc-auth/identity-oidc-auth-service";
import { identityProjectDALFactory } from "@app/services/identity-project/identity-project-dal";
import { identityProjectServiceFactory } from "@app/services/identity-project/identity-project-service";
import { identityTlsCertAuthDALFactory } from "@app/services/identity-tls-cert-auth/identity-tls-cert-auth-dal";
import { identityTlsCertAuthServiceFactory } from "@app/services/identity-tls-cert-auth/identity-tls-cert-auth-service";
import { identityTokenAuthDALFactory } from "@app/services/identity-token-auth/identity-token-auth-dal";
import { identityTokenAuthServiceFactory } from "@app/services/identity-token-auth/identity-token-auth-service";
import { identityUaClientSecretDALFactory } from "@app/services/identity-ua/identity-ua-client-secret-dal";
import { identityUaDALFactory } from "@app/services/identity-ua/identity-ua-dal";
import { identityUaServiceFactory } from "@app/services/identity-ua/identity-ua-service";
import { identityV2DALFactory } from "@app/services/identity-v2/identity-dal";
import { identityV2ServiceFactory } from "@app/services/identity-v2/identity-service";
import { integrationDALFactory } from "@app/services/integration/integration-dal";
import { integrationServiceFactory } from "@app/services/integration/integration-service";
import { integrationAuthDALFactory } from "@app/services/integration-auth/integration-auth-dal";
import { integrationAuthServiceFactory } from "@app/services/integration-auth/integration-auth-service";
import { internalKmsDALFactory } from "@app/services/kms/internal-kms-dal";
import { kmskeyDALFactory } from "@app/services/kms/kms-key-dal";
import { TKmsRootConfigDALFactory } from "@app/services/kms/kms-root-config-dal";
import { kmsServiceFactory } from "@app/services/kms/kms-service";
import { RootKeyEncryptionStrategy } from "@app/services/kms/kms-types";
import { membershipDALFactory } from "@app/services/membership/membership-dal";
import { membershipRoleDALFactory } from "@app/services/membership/membership-role-dal";
import { membershipGroupDALFactory } from "@app/services/membership-group/membership-group-dal";
import { membershipGroupServiceFactory } from "@app/services/membership-group/membership-group-service";
import { membershipIdentityDALFactory } from "@app/services/membership-identity/membership-identity-dal";
import { membershipIdentityServiceFactory } from "@app/services/membership-identity/membership-identity-service";
import { membershipUserDALFactory } from "@app/services/membership-user/membership-user-dal";
import { membershipUserServiceFactory } from "@app/services/membership-user/membership-user-service";
import { mfaSessionServiceFactory } from "@app/services/mfa-session/mfa-session-service";
import { microsoftTeamsIntegrationDALFactory } from "@app/services/microsoft-teams/microsoft-teams-integration-dal";
import { microsoftTeamsServiceFactory } from "@app/services/microsoft-teams/microsoft-teams-service";
import { projectMicrosoftTeamsConfigDALFactory } from "@app/services/microsoft-teams/project-microsoft-teams-config-dal";
import { notificationQueueServiceFactory } from "@app/services/notification/notification-queue";
import { notificationServiceFactory } from "@app/services/notification/notification-service";
import { userNotificationDALFactory } from "@app/services/notification/user-notification-dal";
import { offlineUsageReportDALFactory } from "@app/services/offline-usage-report/offline-usage-report-dal";
import { offlineUsageReportServiceFactory } from "@app/services/offline-usage-report/offline-usage-report-service";
import { incidentContactDALFactory } from "@app/services/org/incident-contacts-dal";
import { orgDALFactory } from "@app/services/org/org-dal";
import { orgServiceFactory } from "@app/services/org/org-service";
import { orgAdminServiceFactory } from "@app/services/org-admin/org-admin-service";
import { orgAssetDALFactory } from "@app/services/org-asset/org-asset-dal";
import { orgMembershipDALFactory } from "@app/services/org-membership/org-membership-dal";
import { pamAccountRotationServiceFactory } from "@app/services/pam-account-rotation/pam-account-rotation-queue";
import { pamSessionExpirationServiceFactory } from "@app/services/pam-session-expiration/pam-session-expiration-queue";
import { dailyExpiringPkiItemAlertQueueServiceFactory } from "@app/services/pki-alert/expiring-pki-item-alert-queue";
import { pkiAlertDALFactory } from "@app/services/pki-alert/pki-alert-dal";
import { pkiAlertServiceFactory } from "@app/services/pki-alert/pki-alert-service";
import { pkiAlertChannelDALFactory } from "@app/services/pki-alert-v2/pki-alert-channel-dal";
import { pkiAlertHistoryDALFactory } from "@app/services/pki-alert-v2/pki-alert-history-dal";
import { pkiAlertV2DALFactory } from "@app/services/pki-alert-v2/pki-alert-v2-dal";
import { pkiAlertV2QueueServiceFactory } from "@app/services/pki-alert-v2/pki-alert-v2-queue";
import { pkiAlertV2ServiceFactory } from "@app/services/pki-alert-v2/pki-alert-v2-service";
import { pkiCollectionDALFactory } from "@app/services/pki-collection/pki-collection-dal";
import { pkiCollectionItemDALFactory } from "@app/services/pki-collection/pki-collection-item-dal";
import { pkiCollectionServiceFactory } from "@app/services/pki-collection/pki-collection-service";
import { pkiSubscriberDALFactory } from "@app/services/pki-subscriber/pki-subscriber-dal";
import { pkiSubscriberQueueServiceFactory } from "@app/services/pki-subscriber/pki-subscriber-queue";
import { pkiSubscriberServiceFactory } from "@app/services/pki-subscriber/pki-subscriber-service";
import { pkiSyncCleanupQueueServiceFactory } from "@app/services/pki-sync/pki-sync-cleanup-queue";
import { pkiSyncDALFactory } from "@app/services/pki-sync/pki-sync-dal";
import { pkiSyncQueueFactory } from "@app/services/pki-sync/pki-sync-queue";
import { pkiSyncServiceFactory } from "@app/services/pki-sync/pki-sync-service";
import { pkiTemplatesDALFactory } from "@app/services/pki-templates/pki-templates-dal";
import { pkiTemplatesServiceFactory } from "@app/services/pki-templates/pki-templates-service";
import { projectDALFactory } from "@app/services/project/project-dal";
import { projectQueueFactory } from "@app/services/project/project-queue";
import { projectServiceFactory } from "@app/services/project/project-service";
import { projectSshConfigDALFactory } from "@app/services/project/project-ssh-config-dal";
import { projectBotDALFactory } from "@app/services/project-bot/project-bot-dal";
import { projectBotServiceFactory } from "@app/services/project-bot/project-bot-service";
import { projectEnvDALFactory } from "@app/services/project-env/project-env-dal";
import { projectEnvServiceFactory } from "@app/services/project-env/project-env-service";
import { projectKeyDALFactory } from "@app/services/project-key/project-key-dal";
import { projectKeyServiceFactory } from "@app/services/project-key/project-key-service";
import { projectMembershipDALFactory } from "@app/services/project-membership/project-membership-dal";
import { projectMembershipServiceFactory } from "@app/services/project-membership/project-membership-service";
import { reminderDALFactory } from "@app/services/reminder/reminder-dal";
import { dailyReminderQueueServiceFactory } from "@app/services/reminder/reminder-queue";
import { reminderServiceFactory } from "@app/services/reminder/reminder-service";
import { reminderRecipientDALFactory } from "@app/services/reminder-recipients/reminder-recipient-dal";
import { dailyResourceCleanUpQueueServiceFactory } from "@app/services/resource-cleanup/resource-cleanup-queue";
import { resourceMetadataDALFactory } from "@app/services/resource-metadata/resource-metadata-dal";
import { roleDALFactory } from "@app/services/role/role-dal";
import { roleServiceFactory } from "@app/services/role/role-service";
import { secretDALFactory } from "@app/services/secret/secret-dal";
import { secretQueueFactory } from "@app/services/secret/secret-queue";
import { secretServiceFactory } from "@app/services/secret/secret-service";
import { secretVersionDALFactory } from "@app/services/secret/secret-version-dal";
import { secretVersionTagDALFactory } from "@app/services/secret/secret-version-tag-dal";
import { secretBlindIndexDALFactory } from "@app/services/secret-blind-index/secret-blind-index-dal";
import { secretBlindIndexServiceFactory } from "@app/services/secret-blind-index/secret-blind-index-service";
import { secretFolderDALFactory } from "@app/services/secret-folder/secret-folder-dal";
import { secretFolderServiceFactory } from "@app/services/secret-folder/secret-folder-service";
import { secretFolderVersionDALFactory } from "@app/services/secret-folder/secret-folder-version-dal";
import { secretImportDALFactory } from "@app/services/secret-import/secret-import-dal";
import { secretImportServiceFactory } from "@app/services/secret-import/secret-import-service";
import { secretReminderRecipientsDALFactory } from "@app/services/secret-reminder-recipients/secret-reminder-recipients-dal";
import { secretSharingDALFactory } from "@app/services/secret-sharing/secret-sharing-dal";
import { secretSharingServiceFactory } from "@app/services/secret-sharing/secret-sharing-service";
import { secretSyncDALFactory } from "@app/services/secret-sync/secret-sync-dal";
import { secretSyncQueueFactory } from "@app/services/secret-sync/secret-sync-queue";
import { secretSyncServiceFactory } from "@app/services/secret-sync/secret-sync-service";
import { secretTagDALFactory } from "@app/services/secret-tag/secret-tag-dal";
import { secretTagServiceFactory } from "@app/services/secret-tag/secret-tag-service";
import { secretV2BridgeDALFactory } from "@app/services/secret-v2-bridge/secret-v2-bridge-dal";
import { secretV2BridgeServiceFactory } from "@app/services/secret-v2-bridge/secret-v2-bridge-service";
import { secretVersionV2BridgeDALFactory } from "@app/services/secret-v2-bridge/secret-version-dal";
import { secretVersionV2TagBridgeDALFactory } from "@app/services/secret-v2-bridge/secret-version-tag-dal";
import { serviceTokenDALFactory } from "@app/services/service-token/service-token-dal";
import { serviceTokenServiceFactory } from "@app/services/service-token/service-token-service";
import { projectSlackConfigDALFactory } from "@app/services/slack/project-slack-config-dal";
import { slackIntegrationDALFactory } from "@app/services/slack/slack-integration-dal";
import { slackServiceFactory } from "@app/services/slack/slack-service";
import { TSmtpService } from "@app/services/smtp/smtp-service";
import { invalidateCacheQueueFactory } from "@app/services/super-admin/invalidate-cache-queue";
import { TSuperAdminDALFactory } from "@app/services/super-admin/super-admin-dal";
import { getServerCfg, superAdminServiceFactory } from "@app/services/super-admin/super-admin-service";
import { telemetryDALFactory } from "@app/services/telemetry/telemetry-dal";
import { telemetryQueueServiceFactory } from "@app/services/telemetry/telemetry-queue";
import { telemetryServiceFactory } from "@app/services/telemetry/telemetry-service";
import { totpConfigDALFactory } from "@app/services/totp/totp-config-dal";
import { totpServiceFactory } from "@app/services/totp/totp-service";
import { upgradePathServiceFactory } from "@app/services/upgrade-path/upgrade-path-service";
import { userDALFactory } from "@app/services/user/user-dal";
import { userServiceFactory } from "@app/services/user/user-service";
import { userAliasDALFactory } from "@app/services/user-alias/user-alias-dal";
import { userEngagementServiceFactory } from "@app/services/user-engagement/user-engagement-service";
import { webAuthnCredentialDALFactory } from "@app/services/webauthn/webauthn-credential-dal";
import { webAuthnServiceFactory } from "@app/services/webauthn/webauthn-service";
import { webhookDALFactory } from "@app/services/webhook/webhook-dal";
import { webhookServiceFactory } from "@app/services/webhook/webhook-service";
import { workflowIntegrationDALFactory } from "@app/services/workflow-integration/workflow-integration-dal";
import { workflowIntegrationServiceFactory } from "@app/services/workflow-integration/workflow-integration-service";

import { injectAuditLogInfo } from "../plugins/audit-log";
import { injectAssumePrivilege } from "../plugins/auth/inject-assume-privilege";
import { injectIdentity } from "../plugins/auth/inject-identity";
import { injectPermission } from "../plugins/auth/inject-permission";
import { injectRateLimits } from "../plugins/inject-rate-limits";
import { forwardWritesToPrimary } from "../plugins/primary-forwarding-mode";
import { registerV1Routes } from "./v1";
import { initializeOauthConfigSync } from "./v1/sso-router";
import { registerV2Routes } from "./v2";
import { registerV3Routes } from "./v3";
import { registerV4Routes } from "./v4";
import { THsmServiceFactory } from "@app/services/hsm/hsm-service";
import { licenseServiceFactory } from "@app/services/license/license-service";
import { rateLimitServiceFactory } from "@app/services/rate-limit/rate-limit-service";
import { isHsmActiveAndEnabled } from "@app/services/hsm/hsm-fns";

const histogram = monitorEventLoopDelay({ resolution: 20 });
histogram.enable();

export const registerRoutes = async (
  server: FastifyZodProvider,
  {
    auditLogDb,
    superAdminDAL,
    db,
    smtp: smtpService,
    queue: queueService,
    keyStore,
    clickhouse,
    envConfig,
    hsmService,
    kmsRootConfigDAL
  }: {
    auditLogDb?: Knex;
    superAdminDAL: TSuperAdminDALFactory;
    db: Knex;
    smtp: TSmtpService;
    queue: TQueueServiceFactory;
    keyStore: TKeyStoreFactory;
    clickhouse: ClickHouseClient | null;
    envConfig: TEnvConfig;
    hsmService: THsmServiceFactory;
    kmsRootConfigDAL: TKmsRootConfigDALFactory;
  }
) => {
  const appCfg = getConfig();
  await server.register(registerSecretScanningV2Webhooks, {
    prefix: "/secret-scanning/webhooks"
  });

  // db layers
  const userDAL = userDALFactory(db);
  const userAliasDAL = userAliasDALFactory(db);
  const authDAL = authDALFactory(db);
  const authTokenDAL = tokenDALFactory(db);
  const orgDAL = orgDALFactory(db);
  const orgMembershipDAL = orgMembershipDALFactory(db);
  const incidentContactDAL = incidentContactDALFactory(db);
  const apiKeyDAL = apiKeyDALFactory(db);

  const projectDAL = projectDALFactory(db);
  const projectSshConfigDAL = projectSshConfigDALFactory(db);
  const projectMembershipDAL = projectMembershipDALFactory(db);
  const projectEnvDAL = projectEnvDALFactory(db);
  const projectKeyDAL = projectKeyDALFactory(db);
  const projectBotDAL = projectBotDALFactory(db);

  const secretDAL = secretDALFactory(db);
  const secretTagDAL = secretTagDALFactory(db);
  const folderDAL = secretFolderDALFactory(db);
  const folderVersionDAL = secretFolderVersionDALFactory(db);
  const secretImportDAL = secretImportDALFactory(db);
  const secretVersionDAL = secretVersionDALFactory(db);
  const secretVersionTagDAL = secretVersionTagDALFactory(db);
  const secretBlindIndexDAL = secretBlindIndexDALFactory(db);

  const secretV2BridgeDAL = secretV2BridgeDALFactory({ db, keyStore });
  const secretVersionV2BridgeDAL = secretVersionV2BridgeDALFactory(db);
  const secretVersionTagV2BridgeDAL = secretVersionV2TagBridgeDALFactory(db);

  const reminderDAL = reminderDALFactory(db);
  const reminderRecipientDAL = reminderRecipientDALFactory(db);
  const queueJobsDAL = queueJobsDALFactory(db);

  const integrationDAL = integrationDALFactory(db);
  const offlineUsageReportDAL = offlineUsageReportDALFactory(db);
  const integrationAuthDAL = integrationAuthDALFactory(db);
  const webhookDAL = webhookDALFactory(db);
  const serviceTokenDAL = serviceTokenDALFactory(db);

  const identityDAL = identityDALFactory(db);
  const identityV2DAL = identityV2DALFactory(db);
  const identityMetadataDAL = identityMetadataDALFactory(db);
  const identityAccessTokenDAL = identityAccessTokenDALFactory(db);
  const identityOrgMembershipDAL = identityOrgDALFactory(db);
  const identityProjectDAL = identityProjectDALFactory(db);

  const identityTokenAuthDAL = identityTokenAuthDALFactory(db);
  const identityUaDAL = identityUaDALFactory(db);
  const identityKubernetesAuthDAL = identityKubernetesAuthDALFactory(db);
  const identityUaClientSecretDAL = identityUaClientSecretDALFactory(db);
  const identityAliCloudAuthDAL = identityAliCloudAuthDALFactory(db);
  const identityTlsCertAuthDAL = identityTlsCertAuthDALFactory(db);
  const identityAwsAuthDAL = identityAwsAuthDALFactory(db);
  const identityGcpAuthDAL = identityGcpAuthDALFactory(db);
  const identityOciAuthDAL = identityOciAuthDALFactory(db);
  const identityOidcAuthDAL = identityOidcAuthDALFactory(db);
  const identityJwtAuthDAL = identityJwtAuthDALFactory(db);
  const identityAzureAuthDAL = identityAzureAuthDALFactory(db);
  const identityLdapAuthDAL = identityLdapAuthDALFactory(db);

  const auditLogDAL = auditLogDALFactory(auditLogDb ?? db);
  const telemetryDAL = telemetryDALFactory(db);
  const appConnectionDAL = appConnectionDALFactory(db);
  const secretSyncDAL = secretSyncDALFactory(db, folderDAL);
  const userNotificationDAL = userNotificationDALFactory(db);

  // ee db layer ops
  const permissionDAL = permissionDALFactory(db);




  const groupProjectDAL = groupProjectDALFactory(db);
  const secretSharingDAL = secretSharingDALFactory(db);
  const orgAssetDAL = orgAssetDALFactory(db);


  const kmsDAL = kmskeyDALFactory(db);
  const internalKmsDAL = internalKmsDALFactory(db);

  const slackIntegrationDAL = slackIntegrationDALFactory(db);
  const projectSlackConfigDAL = projectSlackConfigDALFactory(db);
  const workflowIntegrationDAL = workflowIntegrationDALFactory(db);
  const totpConfigDAL = totpConfigDALFactory(db);
  const webAuthnCredentialDAL = webAuthnCredentialDALFactory(db);

  const externalGroupOrgRoleMappingDAL = externalGroupOrgRoleMappingDALFactory(db);

  const resourceMetadataDAL = resourceMetadataDALFactory(db);

  const secretReminderRecipientsDAL = secretReminderRecipientsDALFactory(db);

  const microsoftTeamsIntegrationDAL = microsoftTeamsIntegrationDALFactory(db);
  const projectMicrosoftTeamsConfigDAL = projectMicrosoftTeamsConfigDALFactory(db);
  const keyValueStoreDAL = keyValueStoreDALFactory(db);

  const membershipDAL = membershipDALFactory(db);
  const membershipUserDAL = membershipUserDALFactory(db);
  const membershipIdentityDAL = membershipIdentityDALFactory(db);
  const membershipGroupDAL = membershipGroupDALFactory(db);
  const additionalPrivilegeDAL = additionalPrivilegeDALFactory(db);
  const membershipRoleDAL = membershipRoleDALFactory(db);
  const roleDAL = roleDALFactory(db);
  const pkiAlertHistoryDAL = pkiAlertHistoryDALFactory(db);
  const pkiAlertChannelDAL = pkiAlertChannelDALFactory(db);
  const pkiAlertV2DAL = pkiAlertV2DALFactory(db);

  const vaultExternalMigrationConfigDAL = vaultExternalMigrationConfigDALFactory(db);

  // New event bus for inter-container communication

  // Project events service (publishes via event bus for inter-container communication)

  const permissionService = permissionServiceFactory({
    permissionDAL,
    serviceTokenDAL,
    projectDAL,
    keyStore,
    roleDAL,
    userDAL,
    identityDAL
  });


  const licenseService = licenseServiceFactory();

  // Project events SSE service (for clients to subscribe to secret mutation events)

  const tokenService = tokenServiceFactory({ tokenDAL: authTokenDAL, userDAL, membershipUserDAL, orgDAL });

  const membershipUserService = membershipUserServiceFactory({
    licenseService,
    membershipRoleDAL,
    membershipUserDAL,
    orgDAL,
    permissionService,
    roleDAL,
    userDAL,
    projectDAL,
    projectKeyDAL,
    smtpService,
    tokenService,
    userAliasDAL,
    additionalPrivilegeDAL
  });

  const membershipIdentityService = membershipIdentityServiceFactory({
    identityDAL,
    membershipIdentityDAL,
    membershipRoleDAL,
    orgDAL,
    permissionService,
    roleDAL,
    additionalPrivilegeDAL
  });

  const membershipGroupService = membershipGroupServiceFactory({
    membershipGroupDAL,
    membershipRoleDAL,
    roleDAL,
    permissionService,
    orgDAL,
  });

  const roleService = roleServiceFactory({
    permissionService,
    roleDAL,
    projectDAL,
    identityDAL,
    userDAL,
    externalGroupOrgRoleMappingDAL,
    membershipRoleDAL
  });
  const additionalPrivilegeService = additionalPrivilegeServiceFactory({
    additionalPrivilegeDAL,
    membershipDAL,
    orgDAL,
    permissionService
  });

  const kmsService = kmsServiceFactory({
    kmsRootConfigDAL,
    keyStore,
    kmsDAL,
    internalKmsDAL,
    orgDAL,
    projectDAL,
    hsmService,
    envConfig
  });




  const auditLogQueue = await auditLogQueueServiceFactory({
    auditLogDAL,
    queueService,
    projectDAL,
    licenseService,
    clickhouseClient: clickhouse
  });

  const notificationQueue = notificationQueueServiceFactory({
    userNotificationDAL,
    queueService
  });

  const notificationService = notificationServiceFactory({ notificationQueue, userNotificationDAL });

  const clickhouseAuditLogDAL = clickhouse
    ? clickhouseAuditLogDALFactory(clickhouse, db, envConfig.CLICKHOUSE_AUDIT_LOG_TABLE_NAME)
    : undefined;

  const auditLogService = auditLogServiceFactory({ auditLogQueue });

  const groupProjectService = groupProjectServiceFactory({
    projectDAL,
    permissionService
  });

  const folderCommitChangesDAL = folderCommitChangesDALFactory(db);
  const folderCheckpointDAL = folderCheckpointDALFactory(db);
  const folderCheckpointResourcesDAL = folderCheckpointResourcesDALFactory(db);
  const folderTreeCheckpointDAL = folderTreeCheckpointDALFactory(db);
  const folderCommitDAL = folderCommitDALFactory(db);
  const folderTreeCheckpointResourcesDAL = folderTreeCheckpointResourcesDALFactory(db);

  const folderCommitQueueService = folderCommitQueueServiceFactory({
    queueService,
    folderTreeCheckpointDAL,
    keyStore,
    folderTreeCheckpointResourcesDAL,
    folderCommitDAL,
    folderDAL
  });
  const folderCommitService = folderCommitServiceFactory({
    folderCommitDAL,
    folderCommitChangesDAL,
    folderCheckpointDAL,
    folderTreeCheckpointDAL,
    userDAL,
    identityDAL,
    folderDAL,
    folderVersionDAL,
    secretVersionV2BridgeDAL,
    projectDAL,
    folderCheckpointResourcesDAL,
    secretV2BridgeDAL,
    folderTreeCheckpointResourcesDAL,
    folderCommitQueueService,
    permissionService,
    kmsService,
    secretTagDAL,
    resourceMetadataDAL
  });



  const telemetryService = telemetryServiceFactory({
    keyStore,
    licenseService
  });
  const telemetryQueue = telemetryQueueServiceFactory({
    keyStore,
    telemetryDAL,
    queueService,
    telemetryService
  });

  const invalidateCacheQueue = invalidateCacheQueueFactory({
    keyStore,
    queueService
  });

  const userService = userServiceFactory({
    userDAL,
    orgDAL,
    tokenService,
    permissionService,
    groupProjectDAL,
    smtpService,
    userAliasDAL,
    membershipUserDAL
  });

  const upgradePathService = upgradePathServiceFactory({ keyStore });

  const totpService = totpServiceFactory({
    totpConfigDAL,
    userDAL,
    kmsService
  });

  const webAuthnService = webAuthnServiceFactory({
    webAuthnCredentialDAL,
    userDAL,
    tokenService,
    keyStore
  });

  const loginService = authLoginServiceFactory({
    userDAL,
    smtpService,
    tokenService,
    orgDAL,
    totpService,
    auditLogService,
    notificationService,
    membershipRoleDAL,
    membershipUserDAL,
    keyStore
  });
  const passwordService = authPaswordServiceFactory({
    tokenService,
    smtpService,
    authDAL,
    userDAL,
    totpConfigDAL
  });

  const accountRecoveryService = accountRecoveryServiceFactory({
    tokenService,
    smtpService,
    userDAL,
    membershipUserDAL
  });

  const projectBotService = projectBotServiceFactory({ permissionService, projectBotDAL, projectDAL });

  const reminderService = reminderServiceFactory({
    reminderDAL,
    reminderRecipientDAL,
    smtpService,
    projectMembershipDAL,
    permissionService,
    secretV2BridgeDAL
  });

  const orgService = orgServiceFactory({
    userAliasDAL,
    identityMetadataDAL,
    secretDAL,
    secretV2BridgeDAL,
    folderDAL,
    licenseService,
    permissionService,
    orgDAL,
    incidentContactDAL,
    tokenService,
    projectDAL,
    projectMembershipDAL,
    orgMembershipDAL,
    projectKeyDAL,
    smtpService,
    userDAL,
    loginService,
    projectBotService,
    reminderService,
    membershipRoleDAL,
    membershipUserDAL,
    roleDAL,
    additionalPrivilegeDAL
  });


  const signupService = authSignupServiceFactory({
    tokenService,
    smtpService,
    authDAL,
    userDAL,
    projectKeyDAL,
    projectDAL,
    projectBotDAL,
    orgDAL,
    orgService,
    licenseService,
    membershipGroupDAL
  });

  const microsoftTeamsService = microsoftTeamsServiceFactory({
    microsoftTeamsIntegrationDAL,
    permissionService,
    workflowIntegrationDAL,
    kmsService,
    serverCfgDAL: superAdminDAL
  });

  const superAdminService = superAdminServiceFactory({
    userDAL,
    identityDAL,
    userAliasDAL,
    identityTokenAuthDAL,
    identityAccessTokenDAL,
    authService: loginService,
    serverCfgDAL: superAdminDAL,
    kmsRootConfigDAL,
    orgService,
    keyStore,
    orgDAL,
    licenseService,
    kmsService,
    microsoftTeamsService,
    invalidateCacheQueue,
    smtpService,
    tokenService,
    membershipIdentityDAL,
    membershipRoleDAL,
    membershipUserDAL
  });

  const offlineUsageReportService = offlineUsageReportServiceFactory({
    offlineUsageReportDAL,
    licenseService
  });

  const orgAdminService = orgAdminServiceFactory({
    smtpService,
    projectDAL,
    permissionService,
    notificationService,
    membershipRoleDAL,
    membershipUserDAL,
    projectMembershipDAL
  });

  const rateLimitService = rateLimitServiceFactory({ db });
  const apiKeyService = apiKeyServiceFactory({ apiKeyDAL, userDAL });


  const projectMembershipService = projectMembershipServiceFactory({
    projectMembershipDAL,
    projectDAL,
    permissionService,
    userDAL,
    smtpService,
    projectKeyDAL,
    groupProjectDAL,
    secretReminderRecipientsDAL,
    licenseService,
    notificationService,
    membershipUserDAL,
    additionalPrivilegeDAL,
    membershipRoleDAL
  });

  const projectKeyService = projectKeyServiceFactory({
    permissionService,
    projectKeyDAL,
    membershipUserDAL
  });

  const projectQueueService = projectQueueFactory({
    queueService,
    secretDAL,
    folderDAL,
    projectDAL,
    orgDAL,
    integrationAuthDAL,
    orgService,
    projectEnvDAL,
    userDAL,
    secretVersionDAL,
    projectKeyDAL,
    projectBotDAL,
    membershipRoleDAL,
    membershipUserDAL
  });

  const certificateAuthorityDAL = certificateAuthorityDALFactory(db);
  const internalCertificateAuthorityDAL = internalCertificateAuthorityDALFactory(db);
  const externalCertificateAuthorityDAL = externalCertificateAuthorityDALFactory(db);
  const certificateAuthorityCertDAL = certificateAuthorityCertDALFactory(db);
  const certificateAuthoritySecretDAL = certificateAuthoritySecretDALFactory(db);
  const certificateTemplateDAL = certificateTemplateDALFactory(db);
  const certificateTemplateEstConfigDAL = certificateTemplateEstConfigDALFactory(db);
  const certificatePolicyDAL = certificatePolicyDALFactory(db);
  const certificateProfileDAL = certificateProfileDALFactory(db);
  const apiEnrollmentConfigDAL = apiEnrollmentConfigDALFactory(db);
  const estEnrollmentConfigDAL = estEnrollmentConfigDALFactory(db);
  const acmeEnrollmentConfigDAL = acmeEnrollmentConfigDALFactory(db);
  const certificateDAL = certificateDALFactory(db);
  const certificateBodyDAL = certificateBodyDALFactory(db);
  const certificateSecretDAL = certificateSecretDALFactory(db);
  const certificateRequestDAL = certificateRequestDALFactory(db);
  const certificateSyncDAL = certificateSyncDALFactory(db);

  const pkiAlertDAL = pkiAlertDALFactory(db);
  const pkiCollectionDAL = pkiCollectionDALFactory(db);
  const pkiCollectionItemDAL = pkiCollectionItemDALFactory(db);
  const pkiSubscriberDAL = pkiSubscriberDALFactory(db);
  const pkiSyncDAL = pkiSyncDALFactory(db);
  const pkiTemplatesDAL = pkiTemplatesDALFactory(db);


  const approvalPolicyDAL = approvalPolicyDALFactory(db);







  const certificateTemplateService = certificateTemplateServiceFactory({
    certificateTemplateDAL,
    certificateTemplateEstConfigDAL,
    certificateAuthorityDAL,
    permissionService,
    kmsService,
    projectDAL,
    licenseService
  });

  const certificatePolicyService = certificatePolicyServiceFactory({
    certificatePolicyDAL,
    permissionService
  });

  const certificateProfileService = certificateProfileServiceFactory({
    certificateProfileDAL,
    certificatePolicyDAL,
    certificatePolicyService,
    apiEnrollmentConfigDAL,
    estEnrollmentConfigDAL,
    acmeEnrollmentConfigDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    certificateAuthorityDAL,
    externalCertificateAuthorityDAL,
    permissionService,
    kmsService,
    projectDAL
  });

  const pkiAlertService = pkiAlertServiceFactory({
    pkiAlertDAL,
    pkiCollectionDAL,
    permissionService,
    smtpService
  });

  const pkiCollectionService = pkiCollectionServiceFactory({
    pkiCollectionDAL,
    pkiCollectionItemDAL,
    certificateAuthorityDAL,
    certificateDAL,
    permissionService
  });


  const integrationAuthService = integrationAuthServiceFactory({
    integrationAuthDAL,
    integrationDAL,
    permissionService,
    projectBotService,
    kmsService
  });




  const secretSyncQueue = secretSyncQueueFactory({
    queueService,
    secretSyncDAL,
    folderDAL,
    secretImportDAL,
    secretV2BridgeDAL,
    kmsService,
    keyStore,
    auditLogService,
    smtpService,
    projectDAL,
    projectMembershipDAL,
    projectBotDAL,
    secretDAL,
    folderCommitService,
    secretBlindIndexDAL,
    secretVersionDAL,
    secretTagDAL,
    secretVersionTagDAL,
    secretVersionV2BridgeDAL,
    secretVersionTagV2BridgeDAL,
    resourceMetadataDAL,
    appConnectionDAL,
    licenseService,
    notificationService,
    projectSlackConfigDAL,
    projectMicrosoftTeamsConfigDAL,
    microsoftTeamsService
  });

  const secretQueueService = secretQueueFactory({
    keyStore,
    queueService,
    secretDAL,
    folderDAL,
    integrationAuthService,
    projectBotService,
    integrationDAL,
    secretImportDAL,
    projectEnvDAL,
    webhookDAL,
    auditLogService,
    userDAL,
    projectMembershipDAL,
    smtpService,
    projectDAL,
    projectBotDAL,
    secretVersionDAL,
    secretBlindIndexDAL,
    secretTagDAL,
    secretVersionTagDAL,
    kmsService,
    secretVersionV2BridgeDAL,
    secretV2BridgeDAL,
    secretVersionTagV2BridgeDAL,
    integrationAuthDAL,
    projectKeyDAL,
    orgService,
    resourceMetadataDAL,
    folderCommitService,
    secretSyncQueue,
    reminderService,
    licenseService,
    membershipRoleDAL,
    membershipUserDAL,
    telemetryService,
  });

  const projectService = projectServiceFactory({
    permissionService,
    projectDAL,
    projectSshConfigDAL,
    projectQueue: projectQueueService,
    userDAL,
    projectEnvDAL,
    orgDAL,
    projectMembershipDAL,
    folderDAL,
    licenseService,
    pkiSubscriberDAL,
    certificateAuthorityDAL,
    certificateDAL,
    pkiAlertDAL,
    pkiCollectionDAL,
    keyStore,
    kmsService,
    certificateTemplateDAL,
    projectSlackConfigDAL,
    slackIntegrationDAL,
    projectMicrosoftTeamsConfigDAL,
    microsoftTeamsIntegrationDAL,
    smtpService,
    notificationService,
    identityDAL,
    membershipGroupDAL,
    membershipIdentityDAL,
    membershipRoleDAL,
    membershipUserDAL,
    roleDAL,
  });

  const projectEnvService = projectEnvServiceFactory({
    permissionService,
    projectEnvDAL,
    keyStore,
    licenseService,
    projectDAL,
    folderDAL,
  });

  const webhookService = webhookServiceFactory({
    permissionService,
    webhookDAL,
    projectEnvDAL,
    projectDAL,
    kmsService
  });

  const secretTagService = secretTagServiceFactory({ secretTagDAL, permissionService });
  const folderService = secretFolderServiceFactory({
    permissionService,
    folderDAL,
    folderVersionDAL,
    projectEnvDAL,
    projectDAL,
    folderCommitService,
    secretV2BridgeDAL,
  });

  const secretImportService = secretImportServiceFactory({
    licenseService,
    projectBotService,
    projectEnvDAL,
    folderDAL,
    permissionService,
    secretImportDAL,
    projectDAL,
    secretDAL,
    secretQueueService,
    secretV2BridgeDAL,
    kmsService
  });
  const secretBlindIndexService = secretBlindIndexServiceFactory({
    permissionService,
    secretDAL,
    secretBlindIndexDAL
  });

  const secretV2BridgeService = secretV2BridgeServiceFactory({
    folderDAL,
    projectDAL,
    secretVersionDAL: secretVersionV2BridgeDAL,
    folderCommitService,
    secretQueueService,
    secretDAL: secretV2BridgeDAL,
    permissionService,
    secretVersionTagDAL: secretVersionTagV2BridgeDAL,
    secretTagDAL,
    projectEnvDAL,
    secretImportDAL,
    kmsService,
    resourceMetadataDAL,
    reminderService,
    keyStore
  });


  const secretService = secretServiceFactory({
    folderDAL,
    secretVersionDAL,
    secretVersionTagDAL,
    secretBlindIndexDAL,
    permissionService,
    projectDAL,
    secretDAL,
    secretTagDAL,
    secretQueueService,
    secretImportDAL,
    projectEnvDAL,
    projectBotService,
    secretV2BridgeService,
    licenseService,
    reminderService,
    secretVersionV2DAL: secretVersionV2BridgeDAL
  });

  const secretSharingService = secretSharingServiceFactory({
    permissionService,
    secretSharingDAL,
    orgAssetDAL,
    orgDAL,
    kmsService,
    smtpService,
    userDAL,
    identityDAL,
    licenseService
  });






  const integrationService = integrationServiceFactory({
    permissionService,
    folderDAL,
    integrationDAL,
    integrationAuthDAL,
    secretQueueService,
    integrationAuthService,
    projectBotService,
    secretV2BridgeDAL,
    secretImportDAL,
    secretDAL,
    kmsService
  });

  const accessTokenQueue = accessTokenQueueServiceFactory({
    keyStore,
    identityAccessTokenDAL,
    queueService,
    serviceTokenDAL
  });

  const serviceTokenService = serviceTokenServiceFactory({
    projectEnvDAL,
    serviceTokenDAL,
    userDAL,
    permissionService,
    projectDAL,
    accessTokenQueue,
    smtpService,
    orgDAL
  });

  const identityService = identityServiceFactory({
    additionalPrivilegeDAL,
    permissionService,
    identityDAL,
    identityOrgMembershipDAL,
    identityProjectDAL,
    licenseService,
    identityMetadataDAL,
    keyStore,
    orgDAL,
    membershipIdentityDAL,
    membershipRoleDAL
  });

  const identityV2Service = identityV2ServiceFactory({
    membershipIdentityDAL,
    membershipRoleDAL,
    identityMetadataDAL,
    licenseService,
    permissionService,
    identityDAL: identityV2DAL,
    keyStore
  });

  const identityProjectService = identityProjectServiceFactory({
    identityProjectDAL,
    membershipIdentityDAL,
    permissionService
  });


  const identityAccessTokenService = identityAccessTokenServiceFactory({
    identityAccessTokenDAL,
    accessTokenQueue,
    identityDAL,
    orgDAL
  });

  const identityTokenAuthService = identityTokenAuthServiceFactory({
    identityDAL,
    identityTokenAuthDAL,
    identityAccessTokenDAL,
    permissionService,
    licenseService,
    orgDAL,
    membershipIdentityDAL
  });

  const identityUaService = identityUaServiceFactory({
    identityDAL,
    permissionService,
    identityAccessTokenDAL,
    identityUaClientSecretDAL,
    identityUaDAL,
    licenseService,
    keyStore,
    orgDAL,
    membershipIdentityDAL
  });

  const identityKubernetesAuthService = identityKubernetesAuthServiceFactory({
    identityDAL,
    identityKubernetesAuthDAL,
    identityAccessTokenDAL,
    permissionService,
    licenseService,
    orgDAL,
    kmsService,
    membershipIdentityDAL
  });
  const identityGcpAuthService = identityGcpAuthServiceFactory({
    identityDAL,
    identityGcpAuthDAL,
    orgDAL,
    identityAccessTokenDAL,
    permissionService,
    licenseService,
    membershipIdentityDAL
  });

  const identityAliCloudAuthService = identityAliCloudAuthServiceFactory({
    identityDAL,
    identityAccessTokenDAL,
    orgDAL,
    identityAliCloudAuthDAL,
    licenseService,
    permissionService,
    membershipIdentityDAL
  });

  const identityTlsCertAuthService = identityTlsCertAuthServiceFactory({
    identityDAL,
    identityAccessTokenDAL,
    identityTlsCertAuthDAL,
    licenseService,
    permissionService,
    kmsService,
    membershipIdentityDAL,
    orgDAL
  });

  const identityAwsAuthService = identityAwsAuthServiceFactory({
    identityDAL,
    identityAccessTokenDAL,
    orgDAL,
    identityAwsAuthDAL,
    licenseService,
    permissionService,
    membershipIdentityDAL
  });

  const identityAzureAuthService = identityAzureAuthServiceFactory({
    identityDAL,
    identityAzureAuthDAL,
    orgDAL,
    identityAccessTokenDAL,
    permissionService,
    licenseService,
    membershipIdentityDAL
  });

  const identityOciAuthService = identityOciAuthServiceFactory({
    identityDAL,
    identityAccessTokenDAL,
    orgDAL,
    identityOciAuthDAL,
    licenseService,
    permissionService,
    membershipIdentityDAL
  });


  const identityOidcAuthService = identityOidcAuthServiceFactory({
    identityDAL,
    identityOidcAuthDAL,
    orgDAL,
    identityAccessTokenDAL,
    permissionService,
    licenseService,
    kmsService,
    membershipIdentityDAL
  });

  const identityJwtAuthService = identityJwtAuthServiceFactory({
    identityDAL,
    identityJwtAuthDAL,
    orgDAL,
    permissionService,
    identityAccessTokenDAL,
    licenseService,
    kmsService,
    membershipIdentityDAL
  });

  const identityLdapAuthService = identityLdapAuthServiceFactory({
    identityLdapAuthDAL,
    orgDAL,
    permissionService,
    kmsService,
    identityAccessTokenDAL,
    licenseService,
    identityDAL,
    keyStore,
    membershipIdentityDAL
  });

  const convertorService = convertorServiceFactory({
    additionalPrivilegeDAL,
    membershipDAL,
    projectDAL,
  });

  const pkiAlertV2Service = pkiAlertV2ServiceFactory({
    pkiAlertV2DAL,
    pkiAlertChannelDAL,
    pkiAlertHistoryDAL,
    permissionService,
    smtpService,
    kmsService,
    notificationService,
    projectMembershipDAL,
    projectDAL
  });

  const pkiAlertV2Queue = pkiAlertV2QueueServiceFactory({
    queueService,
    pkiAlertV2Service,
    pkiAlertV2DAL,
    pkiAlertHistoryDAL
  });




  const approvalRequestDAL = approvalRequestDALFactory(db);
  const approvalRequestGrantsDAL = approvalRequestGrantsDALFactory(db);
  const approvalRequestStepsDAL = approvalRequestStepsDALFactory(db);
  const approvalRequestStepEligibleApproversDAL = approvalRequestStepEligibleApproversDALFactory(db);

  // DAILY
  const dailyResourceCleanUp = dailyResourceCleanUpQueueServiceFactory({
    auditLogDAL,
    queueService,
    secretVersionDAL,
    secretFolderVersionDAL: folderVersionDAL,
    identityAccessTokenDAL,
    secretSharingDAL,
    secretVersionV2DAL: secretVersionV2BridgeDAL,
    identityUniversalAuthClientSecretDAL: identityUaClientSecretDAL,
    serviceTokenService,
    orgService,
    userNotificationDAL,
    keyValueStoreDAL,
    approvalRequestDAL,
    approvalRequestGrantsDAL,
    certificateRequestDAL,
    queueJobsDAL
  });

  const healthAlert = healthAlertServiceFactory({
    queueService,
  });

  const dailyReminderQueueService = dailyReminderQueueServiceFactory({
    reminderService,
    queueService,
    secretDAL: secretV2BridgeDAL,
    secretReminderRecipientsDAL
  });

  const dailyExpiringPkiItemAlert = dailyExpiringPkiItemAlertQueueServiceFactory({
    queueService,
    pkiAlertService
  });


  const userEngagementService = userEngagementServiceFactory({
    userDAL,
    orgDAL
  });

  const slackService = slackServiceFactory({
    permissionService,
    kmsService,
    slackIntegrationDAL,
    workflowIntegrationDAL
  });

  const workflowIntegrationService = workflowIntegrationServiceFactory({
    permissionService,
    workflowIntegrationDAL
  });

  const cmekService = cmekServiceFactory({
    kmsDAL,
    kmsService,
    permissionService
  });

  const externalMigrationQueue = externalMigrationQueueFactory({
    projectEnvService,
    projectDAL,
    projectService,
    smtpService,
    kmsService,
    projectEnvDAL,
    secretVersionDAL: secretVersionV2BridgeDAL,
    secretTagDAL,
    secretVersionTagDAL: secretVersionTagV2BridgeDAL,
    folderDAL,
    secretDAL: secretV2BridgeDAL,
    queueService,
    secretV2BridgeService,
    resourceMetadataDAL,
    folderCommitService,
    folderVersionDAL,
    notificationService
  });

  const externalGroupOrgRoleMappingService = externalGroupOrgRoleMappingServiceFactory({
    permissionService,
    licenseService,
    externalGroupOrgRoleMappingDAL,
    roleDAL
  });

  const appConnectionService = appConnectionServiceFactory({
    appConnectionDAL,
    permissionService,
    kmsService,
    licenseService,
    projectDAL
  });

  const secretSyncService = secretSyncServiceFactory({
    secretSyncDAL,
    secretImportDAL,
    permissionService,
    appConnectionService,
    projectDAL,
    orgDAL,
    folderDAL,
    secretSyncQueue,
    projectBotService,
    keyStore,
    licenseService
  });




  const pkiSyncQueue = pkiSyncQueueFactory({
    queueService,
    kmsService,
    appConnectionDAL,
    keyStore,
    pkiSyncDAL,
    auditLogService,
    projectDAL,
    licenseService,
    certificateDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    certificateAuthorityDAL,
    certificateAuthorityCertDAL,
    certificateSyncDAL
  });

  const pkiSyncCleanup = pkiSyncCleanupQueueServiceFactory({
    queueService,
    pkiSyncDAL,
    pkiSyncQueue
  });

  const internalCaFns = InternalCertificateAuthorityFns({
    certificateAuthorityDAL,
    certificateAuthorityCertDAL,
    certificateAuthoritySecretDAL,
    certificateDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    projectDAL,
    kmsService,
    pkiSyncDAL,
    pkiSyncQueue
  });

  const certificateAuthorityQueue = certificateAuthorityQueueFactory({
    certificateAuthorityDAL,
    certificateAuthoritySecretDAL,
    certificateDAL,
    projectDAL,
    kmsService,
    queueService,
    pkiSubscriberDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    externalCertificateAuthorityDAL,
    keyStore,
    appConnectionDAL,
    appConnectionService,
    pkiSyncDAL,
    pkiSyncQueue
  });

  const internalCertificateAuthorityService = internalCertificateAuthorityServiceFactory({
    certificateAuthorityDAL,
    certificateAuthorityCertDAL,
    certificateAuthoritySecretDAL,
    certificateTemplateDAL,
    certificateAuthorityQueue,
    certificateDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    pkiCollectionDAL,
    pkiCollectionItemDAL,
    projectDAL,
    internalCertificateAuthorityDAL,
    kmsService,
    permissionService
  });

  const certificateAuthorityService = certificateAuthorityServiceFactory({
    certificateAuthorityDAL,
    permissionService,
    appConnectionDAL,
    appConnectionService,
    externalCertificateAuthorityDAL,
    internalCertificateAuthorityService,
    certificateDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    kmsService,
    pkiSubscriberDAL,
    projectDAL,
    pkiSyncDAL,
    pkiSyncQueue
  });


  const pkiSubscriberQueue = pkiSubscriberQueueServiceFactory({
    queueService,
    pkiSubscriberDAL,
    certificateAuthorityDAL,
    certificateAuthorityQueue,
    certificateDAL,
    auditLogService,
    internalCaFns
  });

  const certificateService = certificateServiceFactory({
    certificateDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    certificateAuthorityDAL,
    certificateAuthorityCertDAL,
    certificateAuthoritySecretDAL,
    projectDAL,
    kmsService,
    permissionService,
    pkiCollectionDAL,
    pkiCollectionItemDAL,
    certificateSyncDAL,
    pkiSyncDAL,
    pkiSyncQueue,
    certificateAuthorityService
  });

  const certificateRequestService = certificateRequestServiceFactory({
    certificateRequestDAL,
    certificateDAL,
    certificateService,
    permissionService
  });

  const certificateIssuanceQueue = certificateIssuanceQueueFactory({
    certificateAuthorityDAL,
    appConnectionDAL,
    appConnectionService,
    externalCertificateAuthorityDAL,
    certificateDAL,
    projectDAL,
    kmsService,
    certificateBodyDAL,
    certificateSecretDAL,
    queueService,
    pkiSubscriberDAL,
    pkiSyncDAL,
    pkiSyncQueue,
    certificateProfileDAL,
    certificateRequestService
  });

  const certificateApprovalService = certificateApprovalServiceFactory({
    certificateRequestDAL,
    certificateProfileDAL,
    permissionService,
    certificateAuthorityDAL,
    internalCaService: internalCertificateAuthorityService,
    certificateDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    kmsService,
    projectDAL,
    certificatePolicyService,
    certificateIssuanceQueue
  });

  const approvalPolicyStepsDAL = approvalPolicyStepsDALFactory(db);
  const approvalPolicyStepApproversDAL = approvalPolicyStepApproversDALFactory(db);
  const approvalRequestApprovalsDAL = approvalRequestApprovalsDALFactory(db);

  const approvalPolicyService = approvalPolicyServiceFactory({
    approvalPolicyDAL,
    approvalPolicyStepsDAL,
    approvalPolicyStepApproversDAL,
    permissionService,
    projectMembershipDAL,
    approvalRequestDAL,
    approvalRequestStepsDAL,
    approvalRequestStepEligibleApproversDAL,
    approvalRequestApprovalsDAL,
    notificationService,
    approvalRequestGrantsDAL,
    certificateApprovalService,
    certificateRequestDAL
  });

  const certificateV3Service = certificateV3ServiceFactory({
    certificateDAL,
    certificateSecretDAL,
    certificateAuthorityDAL,
    certificateProfileDAL,
    certificatePolicyService,
    internalCaService: internalCertificateAuthorityService,
    permissionService,
    certificateSyncDAL,
    pkiSyncDAL,
    pkiSyncQueue,
    kmsService,
    projectDAL,
    certificateBodyDAL,
    certificateIssuanceQueue,
    certificateRequestService,
    approvalPolicyDAL,
    certificateRequestDAL,
    userDAL,
    identityDAL,
    approvalPolicyService
  });

  const certificateV3Queue = certificateV3QueueServiceFactory({
    queueService,
    certificateDAL,
    certificateV3Service,
    auditLogService
  });

  const certificateEstV3Service = certificateEstV3ServiceFactory({
    certificateV3Service,
    certificateAuthorityDAL,
    certificateAuthorityCertDAL,
    projectDAL,
    kmsService,
    licenseService,
    certificateProfileDAL,
    estEnrollmentConfigDAL,
    certificatePolicyDAL
  });




  const pkiSubscriberService = pkiSubscriberServiceFactory({
    pkiSubscriberDAL,
    certificateAuthorityDAL,
    certificateAuthorityCertDAL,
    certificateAuthoritySecretDAL,
    certificateDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    projectDAL,
    kmsService,
    permissionService,
    certificateAuthorityQueue,
    internalCaFns,
    pkiSyncDAL,
    pkiSyncQueue
  });

  const pkiSyncService = pkiSyncServiceFactory({
    pkiSyncDAL,
    certificateDAL,
    certificateSyncDAL,
    pkiSubscriberDAL,
    appConnectionService,
    permissionService,
    licenseService,
    pkiSyncQueue
  });




  const pkiTemplateService = pkiTemplatesServiceFactory({
    pkiTemplatesDAL,
    certificateAuthorityDAL,
    certificateAuthorityCertDAL,
    certificateAuthoritySecretDAL,
    certificateDAL,
    certificateBodyDAL,
    certificateSecretDAL,
    projectDAL,
    kmsService,
    permissionService,
    internalCaFns
  });




  const secretAiPolicyDAL = secretAiPolicyDALFactory(db);
  const aiSecretReadRequestDAL = aiSecretReadRequestDALFactory(db);



  const mfaSessionService = mfaSessionServiceFactory({
    keyStore,
    tokenService,
    smtpService,
    totpService
  });

  const pamSessionExpirationService = pamSessionExpirationServiceFactory({
    queueService,
  });


  const pamAccountRotation = pamAccountRotationServiceFactory({
    queueService,
  });





  const secretAiPolicyService = secretAiPolicyServiceFactory({
    secretAiPolicyDAL,
    aiSecretReadRequestDAL,
    projectEnvDAL
  });


  const migrationService = externalMigrationServiceFactory({
    externalMigrationQueue,
    userDAL,
    permissionService,
    kmsService,
    appConnectionService,
    vaultExternalMigrationConfigDAL,
    secretService,
    auditLogService,
  });

  // setup the communication with license key server
  await licenseService.init();

  // If FIPS is enabled, we check to ensure that the users license includes FIPS mode.
  crypto.verifyFipsLicense(licenseService);

  await superAdminService.initServerCfg();

  // Start HSM service if it's configured/enabled.
  await hsmService.startService();

  const hsmStatus = await isHsmActiveAndEnabled({
    hsmService,
    kmsRootConfigDAL,
    licenseService
  });

  // if the encryption strategy is software - user needs to provide an encryption key
  // if the encryption strategy is null AND the hsm is not configured - user needs to provide an encryption key
  const needsEncryptionKey =
    hsmStatus.rootKmsConfigEncryptionStrategy === RootKeyEncryptionStrategy.Software ||
    (hsmStatus.rootKmsConfigEncryptionStrategy === null && !hsmStatus.isHsmConfigured);

  if (needsEncryptionKey) {
    if (!envConfig.ROOT_ENCRYPTION_KEY && !envConfig.ENCRYPTION_KEY) {
      throw new BadRequestError({
        message:
          "Root KMS encryption strategy is set to software. Please set the ENCRYPTION_KEY environment variable and restart your deployment.\nYou can enable HSM encryption in the Server Console."
      });
    }
  }

  await kmsService.startService(hsmStatus);
  await telemetryQueue.startTelemetryCheck();
  await telemetryQueue.startAggregatedEventsJob();
  await dailyResourceCleanUp.init();
  await healthAlert.init();
  await pkiSyncCleanup.init();
  await pamAccountRotation.init();
  pamSessionExpirationService.init();
  await dailyReminderQueueService.startDailyRemindersJob();
  await dailyReminderQueueService.startSecretReminderMigrationJob();
  await dailyExpiringPkiItemAlert.startSendingAlerts();
  await pkiSubscriberQueue.startDailyAutoRenewalJob();
  await pkiAlertV2Queue.init();
  await certificateV3Queue.init();
  await microsoftTeamsService.start();

  // inject all services
  server.decorate<FastifyZodProvider["services"]>("services", {
    login: loginService,
    password: passwordService,
    accountRecovery: accountRecoveryService,
    signup: signupService,
    user: userService,
    groupProject: groupProjectService,
    permission: permissionService,
    org: orgService,
    apiKey: apiKeyService,
    authToken: tokenService,
    superAdmin: superAdminService,
    offlineUsageReport: offlineUsageReportService,
    project: projectService,
    projectMembership: projectMembershipService,
    projectKey: projectKeyService,
    projectEnv: projectEnvService,
    secret: secretService,
    secretTag: secretTagService,
    rateLimit: rateLimitService,
    folder: folderService,
    secretImport: secretImportService,
    projectBot: projectBotService,
    integration: integrationService,
    integrationAuth: integrationAuthService,
    webhook: webhookService,
    serviceToken: serviceTokenService,
    identityV1: identityService,
    identityV2: identityV2Service,
    identityAccessToken: identityAccessTokenService,
    identityTokenAuth: identityTokenAuthService,
    identityUa: identityUaService,
    identityKubernetesAuth: identityKubernetesAuthService,
    identityGcpAuth: identityGcpAuthService,
    identityAliCloudAuth: identityAliCloudAuthService,
    identityAwsAuth: identityAwsAuthService,
    identityAzureAuth: identityAzureAuthService,
    identityOciAuth: identityOciAuthService,
    identityTlsCertAuth: identityTlsCertAuthService,
    identityOidcAuth: identityOidcAuthService,
    identityJwtAuth: identityJwtAuthService,
    identityLdapAuth: identityLdapAuthService,
    auditLog: auditLogService,
    certificate: certificateService,
    certificateV3: certificateV3Service,
    certificateRequest: certificateRequestService,
    certificateEstV3: certificateEstV3Service,
    certificateAuthority: certificateAuthorityService,
    internalCertificateAuthority: internalCertificateAuthorityService,
    certificateTemplate: certificateTemplateService,
    certificatePolicy: certificatePolicyService,
    certificateProfile: certificateProfileService,
    pkiAlert: pkiAlertService,
    pkiCollection: pkiCollectionService,
    pkiSubscriber: pkiSubscriberService,
    pkiSync: pkiSyncService,
    pkiTemplate: pkiTemplateService,
    license: licenseService,
    secretBlindIndex: secretBlindIndexService,
    telemetry: telemetryService,
    secretSharing: secretSharingService,
    userEngagement: userEngagementService,
    hsm: hsmService,
    cmek: cmekService,
    orgAdmin: orgAdminService,
    slack: slackService,
    workflowIntegration: workflowIntegrationService,
    migration: migrationService,
    externalGroupOrgRoleMapping: externalGroupOrgRoleMappingService,
    totp: totpService,
    webAuthn: webAuthnService,
    appConnection: appConnectionService,
    secretSync: secretSyncService,
    microsoftTeams: microsoftTeamsService,
    folderCommit: folderCommitService,
    reminder: reminderService,
    notification: notificationService,
    mfaSession: mfaSessionService,
    upgradePath: upgradePathService,

    membershipUser: membershipUserService,
    membershipIdentity: membershipIdentityService,
    membershipGroup: membershipGroupService,
    role: roleService,
    additionalPrivilege: additionalPrivilegeService,
    identityProject: identityProjectService,
    convertor: convertorService,
    pkiAlertV2: pkiAlertV2Service,
    secretAiPolicy: secretAiPolicyService,
    approvalPolicy: approvalPolicyService
  });

  const cronJobs: CronJob[] = [];
  if (appCfg.isProductionMode) {
    const rateLimitSyncJob = await rateLimitService.initializeBackgroundSync();
    if (rateLimitSyncJob) {
      cronJobs.push(rateLimitSyncJob);
    }
    const licenseSyncJob = await licenseService.initializeBackgroundSync();
    if (licenseSyncJob) {
      cronJobs.push(licenseSyncJob);
    }

    const microsoftTeamsSyncJob = await microsoftTeamsService.initializeBackgroundSync();
    if (microsoftTeamsSyncJob) {
      cronJobs.push(microsoftTeamsSyncJob);
    }

    const adminIntegrationsSyncJob = await superAdminService.initializeAdminIntegrationConfigSync();
    if (adminIntegrationsSyncJob) {
      cronJobs.push(adminIntegrationsSyncJob);
    }
  }

  const configSyncJob = await superAdminService.initializeEnvConfigSync();
  if (configSyncJob) {
    cronJobs.push(configSyncJob);
  }

  const oauthConfigSyncJob = await initializeOauthConfigSync();
  if (oauthConfigSyncJob) {
    cronJobs.push(oauthConfigSyncJob);
  }

  server.decorate<FastifyZodProvider["store"]>("store", {
    user: userDAL,
  });
  const shouldForwardWritesToPrimaryInstance = Boolean(envConfig.KMS_PRIMARY_INSTANCE_URL);
  if (shouldForwardWritesToPrimaryInstance) {
    logger.info(`KMS primary instance is configured: ${envConfig.KMS_PRIMARY_INSTANCE_URL}`);

    await server.register(forwardWritesToPrimary, { primaryUrl: envConfig.KMS_PRIMARY_INSTANCE_URL as string });
  }

  await server.register(injectIdentity, { shouldForwardWritesToPrimaryInstance });
  await server.register(injectAssumePrivilege);
  await server.register(injectPermission);
  await server.register(injectRateLimits);
  await server.register(injectAuditLogInfo);

  server.route({
    method: "GET",
    url: "/api/status",
    config: {
      rateLimit: readLimit
    },
    schema: {
      response: {
        200: z.object({
          date: z.date(),
          message: z.string().optional(),
          emailConfigured: z.boolean().optional(),
          inviteOnlySignup: z.boolean().optional(),
          redisConfigured: z.boolean().optional(),
          secretScanningConfigured: z.boolean().optional(),
          samlDefaultOrgSlug: z.string().optional(),
          auditLogStorageDisabled: z.boolean().optional()
        })
      }
    },
    handler: async () => {
      const cfg = getConfig();
      const serverCfg = await getServerCfg();

      const meanLagMs = histogram.mean / 1e6;
      const maxLagMs = histogram.max / 1e6;
      const p99LagMs = histogram.percentile(99) / 1e6;

      logger.info(
        `Event loop stats - Mean: ${meanLagMs.toFixed(2)}ms, Max: ${maxLagMs.toFixed(2)}ms, p99: ${p99LagMs.toFixed(
          2
        )}ms`
      );

      logger.info(`Raw event loop stats: ${JSON.stringify(histogram, null, 2)}`);

      return {
        date: new Date(),
        message: "Ok",
        emailConfigured: cfg.isSmtpConfigured,
        inviteOnlySignup: Boolean(serverCfg.allowSignUp),
        redisConfigured: cfg.isRedisConfigured,
        secretScanningConfigured: cfg.isSecretScanningConfigured,
        samlDefaultOrgSlug: cfg.samlDefaultOrgSlug,
        auditLogStorageDisabled: Boolean(cfg.DISABLE_AUDIT_LOG_STORAGE)
      };
    }
  });

  // register routes for v1
  await server.register(
    async (v1Server) => {
      await v1Server.register(registerV1Routes);
    },
    { prefix: "/api/v1" }
  );
  await server.register(
    async (v2Server) => {
      await v2Server.register(registerV2Routes);
    },
    { prefix: "/api/v2" }
  );
  await server.register(registerV3Routes, { prefix: "/api/v3" });
  await server.register(registerV4Routes, { prefix: "/api/v4" });

  // Note: This is a special route for BDD tests. It's only available in development mode and only for BDD tests.
  // This route should NEVER BE ENABLED IN PRODUCTION!
  if (getConfig().isBddNockApiEnabled) {
    await server.register(registerBddNockRouter, { prefix: "/api/__bdd_nock__" });
  }

  server.addHook("onClose", async () => {
    cronJobs.forEach((job) => job.stop());
    await telemetryService.flushAll();
  });
};
