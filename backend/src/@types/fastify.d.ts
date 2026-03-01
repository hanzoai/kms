import "fastify";

import { Cluster, Redis } from "ioredis";

import { TUsers } from "@app/db/schemas";
import { TSecretAiPolicyServiceFactory } from "@app/services/secret-ai-policy/secret-ai-policy-service";
import { TAuditLogServiceFactory, TCreateAuditLogDTO } from "@app/services/audit-log/audit-log-types";
import { TPermissionServiceFactory } from "@app/services/permission/permission-service-types";
import { TAuthMode } from "@app/server/plugins/auth/inject-identity";
import { TAccountRecoveryServiceFactory } from "@app/services/account-recovery/account-recovery-service";
import { TAdditionalPrivilegeServiceFactory } from "@app/services/additional-privilege/additional-privilege-service";
import { TApiKeyServiceFactory } from "@app/services/api-key/api-key-service";
import { TAppConnectionServiceFactory } from "@app/services/app-connection/app-connection-service";
import { TApprovalPolicyServiceFactory } from "@app/services/approval-policy/approval-policy-service";
import { TAuthLoginFactory } from "@app/services/auth/auth-login-service";
import { TAuthPasswordFactory } from "@app/services/auth/auth-password-service";
import { TAuthSignupFactory } from "@app/services/auth/auth-signup-service";
import { ActorAuthMethod, ActorType } from "@app/services/auth/auth-type";
import { TAuthTokenServiceFactory } from "@app/services/auth-token/auth-token-service";
import { TCertificateServiceFactory } from "@app/services/certificate/certificate-service";
import { TCertificateAuthorityServiceFactory } from "@app/services/certificate-authority/certificate-authority-service";
import { TInternalCertificateAuthorityServiceFactory } from "@app/services/certificate-authority/internal/internal-certificate-authority-service";
import { TCertificateEstV3ServiceFactory } from "@app/services/certificate-est-v3/certificate-est-v3-service";
import { TCertificatePolicyServiceFactory } from "@app/services/certificate-policy/certificate-policy-service";
import { TCertificateProfileServiceFactory } from "@app/services/certificate-profile/certificate-profile-service";
import { TCertificateRequestServiceFactory } from "@app/services/certificate-request/certificate-request-service";
import { TCertificateTemplateServiceFactory } from "@app/services/certificate-template/certificate-template-service";
import { TCertificateV3ServiceFactory } from "@app/services/certificate-v3/certificate-v3-service";
import { TCmekServiceFactory } from "@app/services/cmek/cmek-service";
import { TConvertorServiceFactory } from "@app/services/convertor/convertor-service";
import { TExternalGroupOrgRoleMappingServiceFactory } from "@app/services/external-group-org-role-mapping/external-group-org-role-mapping-service";
import { TExternalMigrationServiceFactory } from "@app/services/external-migration/external-migration-service";
import { TFolderCommitServiceFactory } from "@app/services/folder-commit/folder-commit-service";
import { TGroupProjectServiceFactory } from "@app/services/group-project/group-project-service";
import { TIdentityServiceFactory } from "@app/services/identity/identity-service";
import { TIdentityAccessTokenServiceFactory } from "@app/services/identity-access-token/identity-access-token-service";
import { TIdentityAliCloudAuthServiceFactory } from "@app/services/identity-alicloud-auth/identity-alicloud-auth-service";
import { TIdentityAwsAuthServiceFactory } from "@app/services/identity-aws-auth/identity-aws-auth-service";
import { TIdentityAzureAuthServiceFactory } from "@app/services/identity-azure-auth/identity-azure-auth-service";
import { TIdentityGcpAuthServiceFactory } from "@app/services/identity-gcp-auth/identity-gcp-auth-service";
import { TIdentityJwtAuthServiceFactory } from "@app/services/identity-jwt-auth/identity-jwt-auth-service";
import { TIdentityKubernetesAuthServiceFactory } from "@app/services/identity-kubernetes-auth/identity-kubernetes-auth-service";
import { TIdentityLdapAuthServiceFactory } from "@app/services/identity-ldap-auth/identity-ldap-auth-service";
import { TAllowedFields } from "@app/services/identity-ldap-auth/identity-ldap-auth-types";
import { TIdentityOciAuthServiceFactory } from "@app/services/identity-oci-auth/identity-oci-auth-service";
import { TIdentityOidcAuthServiceFactory } from "@app/services/identity-oidc-auth/identity-oidc-auth-service";
import { TIdentityProjectServiceFactory } from "@app/services/identity-project/identity-project-service";
import { TIdentityTlsCertAuthServiceFactory } from "@app/services/identity-tls-cert-auth/identity-tls-cert-auth-types";
import { TIdentityTokenAuthServiceFactory } from "@app/services/identity-token-auth/identity-token-auth-service";
import { TIdentityUaServiceFactory } from "@app/services/identity-ua/identity-ua-service";
import { TScopedIdentityV2ServiceFactory } from "@app/services/identity-v2/identity-service";
import { TIntegrationServiceFactory } from "@app/services/integration/integration-service";
import { TIntegrationAuthServiceFactory } from "@app/services/integration-auth/integration-auth-service";
import { TMembershipGroupServiceFactory } from "@app/services/membership-group/membership-group-service";
import { TMembershipIdentityServiceFactory } from "@app/services/membership-identity/membership-identity-service";
import { TMembershipUserServiceFactory } from "@app/services/membership-user/membership-user-service";
import { TMfaSessionServiceFactory } from "@app/services/mfa-session/mfa-session-service";
import { TMicrosoftTeamsServiceFactory } from "@app/services/microsoft-teams/microsoft-teams-service";
import { TNotificationServiceFactory } from "@app/services/notification/notification-service";
import { TOfflineUsageReportServiceFactory } from "@app/services/offline-usage-report/offline-usage-report-service";
import { TOrgServiceFactory } from "@app/services/org/org-service";
import { TOrgAdminServiceFactory } from "@app/services/org-admin/org-admin-service";
import { TPkiAlertServiceFactory } from "@app/services/pki-alert/pki-alert-service";
import { TPkiAlertV2ServiceFactory } from "@app/services/pki-alert-v2/pki-alert-v2-service";
import { TPkiCollectionServiceFactory } from "@app/services/pki-collection/pki-collection-service";
import { TPkiSubscriberServiceFactory } from "@app/services/pki-subscriber/pki-subscriber-service";
import { TPkiSyncServiceFactory } from "@app/services/pki-sync/pki-sync-service";
import { TPkiTemplatesServiceFactory } from "@app/services/pki-templates/pki-templates-service";
import { TProjectServiceFactory } from "@app/services/project/project-service";
import { TProjectBotServiceFactory } from "@app/services/project-bot/project-bot-service";
import { TProjectEnvServiceFactory } from "@app/services/project-env/project-env-service";
import { TProjectKeyServiceFactory } from "@app/services/project-key/project-key-service";
import { TProjectMembershipServiceFactory } from "@app/services/project-membership/project-membership-service";
import { TReminderServiceFactory } from "@app/services/reminder/reminder-types";
import { TRoleServiceFactory } from "@app/services/role/role-service";
import { TSecretServiceFactory } from "@app/services/secret/secret-service";
import { TSecretBlindIndexServiceFactory } from "@app/services/secret-blind-index/secret-blind-index-service";
import { TSecretFolderServiceFactory } from "@app/services/secret-folder/secret-folder-service";
import { TSecretImportServiceFactory } from "@app/services/secret-import/secret-import-service";
import { TSecretReplicationServiceFactory } from "@app/services/secret-replication/secret-replication-service";
import { TSecretSharingServiceFactory } from "@app/services/secret-sharing/secret-sharing-service";
import { TSecretSyncServiceFactory } from "@app/services/secret-sync/secret-sync-service";
import { TSecretTagServiceFactory } from "@app/services/secret-tag/secret-tag-service";
import { TServiceTokenServiceFactory } from "@app/services/service-token/service-token-service";
import { TSlackServiceFactory } from "@app/services/slack/slack-service";
import { TSuperAdminServiceFactory } from "@app/services/super-admin/super-admin-service";
import { TTelemetryServiceFactory } from "@app/services/telemetry/telemetry-service";
import { TTotpServiceFactory } from "@app/services/totp/totp-service";
import { TUpgradePathService } from "@app/services/upgrade-path/upgrade-path-service";
import { TUserDALFactory } from "@app/services/user/user-dal";
import { TUserServiceFactory } from "@app/services/user/user-service";
import { TUserEngagementServiceFactory } from "@app/services/user-engagement/user-engagement-service";
import { TWebAuthnServiceFactory } from "@app/services/webauthn/webauthn-service";
import { TWebhookServiceFactory } from "@app/services/webhook/webhook-service";
import { TWorkflowIntegrationServiceFactory } from "@app/services/workflow-integration/workflow-integration-service";
import { TLicenseServiceFactory } from "@app/services/license/license-service";
import { TRateLimitServiceFactory } from "@app/services/rate-limit/rate-limit-service";
import { THsmServiceFactory } from "@app/services/hsm/hsm-service";
import { TIdentityV2ServiceFactory } from "@app/services/identity-v2/identity-service";

declare module "@fastify/request-context" {
  interface RequestContextData {
    reqId: string;
    ip?: string;
    userAgent?: string;
    orgId?: string;
    orgName?: string;
    userAuthInfo?: {
      userId: string;
      email: string;
    };
    projectDetails?: {
      id: string;
      name: string;
      slug: string;
    };
    identityAuthInfo?: {
      identityId: string;
      identityName: string;
      authMethod: string;
      oidc?: {
        claims: Record<string, string>;
      };
      kubernetes?: {
        namespace: string;
        name: string;
      };
      aws?: {
        accountId: string;
        arn: string;
        userId: string;
        partition: string;
        service: string;
        resourceType: string;
        resourceName: string;
      };
    };
    identityPermissionMetadata?: Record<string, unknown>; // filled by permission service
    assumedPrivilegeDetails?: { requesterId: string; actorId: string; actorType: ActorType; projectId: string };
  }
}

type RateLimitConfiguration = {
  readLimit: number;
  writeLimit: number;
  secretsLimit: number;
  publicEndpointLimit: number;
  authRateLimit: number;
  inviteUserRateLimit: number;
  mfaRateLimit: number;
  identityCreationLimit: number;
  projectCreationLimit: number;
};

declare module "fastify" {
  interface Session {
    callbackPort: string;
    isAdminLogin: boolean;
    orgSlug?: string;
  }

  interface FastifyRequest {
    realIp: string;
    // used for mfa session authentication
    mfa: {
      userId: string;
      orgId?: string;
      user: TUsers;
    };
    // identity injection. depending on which kinda of token the information is filled in auth
    auth: TAuthMode;
    shouldForwardWritesToPrimaryInstance: boolean;
    permission: {
      authMethod: ActorAuthMethod;
      type: ActorType;
      id: string;
      orgId: string;
      parentOrgId: string;
      rootOrgId: string;
    };
    rateLimits: RateLimitConfiguration;
    // passport data
    passportUser: {
      isUserCompleted: boolean;
      providerAuthToken: string;
      externalProviderAccessToken?: string;
    };
    passportMachineIdentity: {
      identityId: string;
      user: {
        uid: string;
        mail?: string;
      };
    };
    kmipUser: {
      projectId: string;
      clientId: string;
      name: string;
    };
    auditLogInfo: Pick<TCreateAuditLogDTO, "userAgent" | "userAgentType" | "ipAddress" | "actor">;
  }

  interface FastifyInstance {
    redis: Redis | Cluster;
    services: {
      login: TAuthLoginFactory;
      password: TAuthPasswordFactory;
      accountRecovery: TAccountRecoveryServiceFactory;
      signup: TAuthSignupFactory;
      authToken: TAuthTokenServiceFactory;
      permission: TPermissionServiceFactory;
      org: TOrgServiceFactory;
      superAdmin: TSuperAdminServiceFactory;
      user: TUserServiceFactory;
      groupProject: TGroupProjectServiceFactory;
      apiKey: TApiKeyServiceFactory;
      pkiAlert: TPkiAlertServiceFactory;
      project: TProjectServiceFactory;
      projectMembership: TProjectMembershipServiceFactory;
      projectEnv: TProjectEnvServiceFactory;
      projectKey: TProjectKeyServiceFactory;
      secret: TSecretServiceFactory;
      secretReplication: TSecretReplicationServiceFactory;
      secretTag: TSecretTagServiceFactory;
      secretImport: TSecretImportServiceFactory;
      projectBot: TProjectBotServiceFactory;
      folder: TSecretFolderServiceFactory;
      integration: TIntegrationServiceFactory;
      integrationAuth: TIntegrationAuthServiceFactory;
      webhook: TWebhookServiceFactory;
      serviceToken: TServiceTokenServiceFactory;
      identityV1: TIdentityServiceFactory;
      identityV2: TScopedIdentityV2ServiceFactory;
      identityAccessToken: TIdentityAccessTokenServiceFactory;
      identityProject: TIdentityProjectServiceFactory;
      identityTokenAuth: TIdentityTokenAuthServiceFactory;
      identityUa: TIdentityUaServiceFactory;
      identityKubernetesAuth: TIdentityKubernetesAuthServiceFactory;
      identityGcpAuth: TIdentityGcpAuthServiceFactory;
      identityAliCloudAuth: TIdentityAliCloudAuthServiceFactory;
      identityTlsCertAuth: TIdentityTlsCertAuthServiceFactory;
      identityAwsAuth: TIdentityAwsAuthServiceFactory;
      identityAzureAuth: TIdentityAzureAuthServiceFactory;
      identityOciAuth: TIdentityOciAuthServiceFactory;
      identityOidcAuth: TIdentityOidcAuthServiceFactory;
      identityJwtAuth: TIdentityJwtAuthServiceFactory;
      identityLdapAuth: TIdentityLdapAuthServiceFactory;
      auditLog: TAuditLogServiceFactory;
      certificate: TCertificateServiceFactory;
      certificateV3: TCertificateV3ServiceFactory;
      certificateRequest: TCertificateRequestServiceFactory;
      certificateTemplate: TCertificateTemplateServiceFactory;
      certificatePolicy: TCertificatePolicyServiceFactory;
      certificateProfile: TCertificateProfileServiceFactory;
      certificateAuthority: TCertificateAuthorityServiceFactory;
      certificateEstV3: TCertificateEstV3ServiceFactory;
      pkiCollection: TPkiCollectionServiceFactory;
      pkiSubscriber: TPkiSubscriberServiceFactory;
      pkiSync: TPkiSyncServiceFactory;
      secretBlindIndex: TSecretBlindIndexServiceFactory;
      telemetry: TTelemetryServiceFactory;
      secretSharing: TSecretSharingServiceFactory;
      userEngagement: TUserEngagementServiceFactory;
      orgAdmin: TOrgAdminServiceFactory;
      slack: TSlackServiceFactory;
      workflowIntegration: TWorkflowIntegrationServiceFactory;
      cmek: TCmekServiceFactory;
      migration: TExternalMigrationServiceFactory;
      externalGroupOrgRoleMapping: TExternalGroupOrgRoleMappingServiceFactory;
      totp: TTotpServiceFactory;
      webAuthn: TWebAuthnServiceFactory;
      appConnection: TAppConnectionServiceFactory;
      secretSync: TSecretSyncServiceFactory;
      microsoftTeams: TMicrosoftTeamsServiceFactory;
      folderCommit: TFolderCommitServiceFactory;
      internalCertificateAuthority: TInternalCertificateAuthorityServiceFactory;
      pkiTemplate: TPkiTemplatesServiceFactory;
      reminder: TReminderServiceFactory;
      notification: TNotificationServiceFactory;
      offlineUsageReport: TOfflineUsageReportServiceFactory;
      mfaSession: TMfaSessionServiceFactory;
      upgradePath: TUpgradePathService;

      membershipUser: TMembershipUserServiceFactory;
      membershipIdentity: TMembershipIdentityServiceFactory;
      membershipGroup: TMembershipGroupServiceFactory;
      additionalPrivilege: TAdditionalPrivilegeServiceFactory;
      role: TRoleServiceFactory;
      convertor: TConvertorServiceFactory;
      pkiAlertV2: TPkiAlertV2ServiceFactory;
      secretAiPolicy: TSecretAiPolicyServiceFactory;
      approvalPolicy: TApprovalPolicyServiceFactory;
      license: TLicenseServiceFactory;
      rateLimit: TRateLimitServiceFactory;
      hsm: THsmServiceFactory;
    };
    // this is exclusive use for middlewares in which we need to inject data
    // everywhere else access using service layer
    store: {
      user: Pick<TUserDALFactory, "findById">;
    };
  }
}
