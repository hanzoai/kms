import {
  AcmeAccountActor,
  AcmeProfileActor,
  EstAccountActor,
  IdentityActor,
  KmipClientActor,
  PlatformActor,
  ScimClientActor,
  ServiceActor,
  UnknownUserActor,
  UserActor
} from "@app/services/audit-log/audit-log-types";

export enum InsightsEventTypes {
  SecretPush = "secrets pushed",
  SecretPulled = "secrets pulled",
  SecretCreated = "secrets added",
  SecretUpdated = "secrets modified",
  SecretDeleted = "secrets deleted",
  AdminInit = "admin initialization",
  UserSignedUp = "User Signed Up",
  SecretRotated = "secrets rotated",
  SecretScannerFull = "historical cloud secret scan",
  SecretScannerPush = "cloud secret scan",
  ProjectCreated = "Project Created",
  IntegrationCreated = "Integration Created",
  IntegrationSynced = "Integration Synced",
  IntegrationDeleted = "Integration Deleted",
  MachineIdentityCreated = "Machine Identity Created",
  UserOrgInvitation = "User Org Invitation",
  TelemetryInstanceStats = "Self Hosted Instance Stats",
  SecretRequestCreated = "Secret Request Created",
  SecretRequestDeleted = "Secret Request Deleted",
  SignSshKey = "Sign SSH Key",
  IssueSshCreds = "Issue SSH Credentials",
  IssueSshHostUserCert = "Issue SSH Host User Certificate",
  IssueSshHostHostCert = "Issue SSH Host Host Certificate",
  SignCert = "Sign PKI Certificate",
  IssueCert = "Issue PKI Certificate",
  InvalidateCache = "Invalidate Cache",
  NotificationUpdated = "Notification Updated"
}

export type TSecretModifiedEvent = {
  event:
    | InsightsEventTypes.SecretPush
    | InsightsEventTypes.SecretRotated
    | InsightsEventTypes.SecretPulled
    | InsightsEventTypes.SecretCreated
    | InsightsEventTypes.SecretUpdated
    | InsightsEventTypes.SecretDeleted;
  properties: {
    numberOfSecrets: number;
    environment: string;
    projectId: string;
    secretPath: string;
    channel?: string;
    userAgent?: string;
    actor?:
      | UserActor
      | IdentityActor
      | ServiceActor
      | ScimClientActor
      | PlatformActor
      | UnknownUserActor
      | AcmeAccountActor
      | AcmeProfileActor
      | KmipClientActor
      | EstAccountActor;
  };
};

export type TAdminInitEvent = {
  event: InsightsEventTypes.AdminInit;
  properties: {
    username: string;
    email: string;
    firstName: string;
    lastName: string;
  };
};

export type TUserSignedUpEvent = {
  event: InsightsEventTypes.UserSignedUp;
  properties: {
    username: string;
    email: string;
    attributionSource?: string;
  };
};

export type TSecretScannerEvent = {
  event: InsightsEventTypes.SecretScannerFull | InsightsEventTypes.SecretScannerPush;
  properties: {
    numberOfRisks: number;
  };
};

export type TProjectCreateEvent = {
  event: InsightsEventTypes.ProjectCreated;
  properties: {
    name: string;
    orgId: string;
  };
};

export type TMachineIdentityCreatedEvent = {
  event: InsightsEventTypes.MachineIdentityCreated;
  properties: {
    name: string;
    hasDeleteProtection: boolean;
    orgId: string;
    identityId: string;
  };
};

export type TIntegrationCreatedEvent = {
  event: InsightsEventTypes.IntegrationCreated;
  properties: {
    projectId: string;
    integrationId: string;
    integration: string; // TODO: fix type
    environment: string;
    secretPath: string;
    url?: string;
    app?: string;
    appId?: string;
    targetEnvironment?: string;
    targetEnvironmentId?: string;
    targetService?: string;
    targetServiceId?: string;
    path?: string;
    region?: string;
  };
};

export type TIntegrationSyncedEvent = {
  event: InsightsEventTypes.IntegrationSynced;
  properties: {
    projectId: string;
    integrationId: string;
    integration: string;
    environment: string;
    secretPath: string;
    isManualSync: boolean;
    url?: string;
    app?: string;
    appId?: string;
    targetEnvironment?: string;
    targetEnvironmentId?: string;
    targetService?: string;
    targetServiceId?: string;
    path?: string;
    region?: string;
  };
};

export type TIntegrationDeletedEvent = {
  event: InsightsEventTypes.IntegrationDeleted;
  properties: {
    projectId: string;
    integrationId: string;
    integration: string;
    environment: string;
    secretPath: string;
    url?: string;
    app?: string;
    appId?: string;
    targetEnvironment?: string;
    targetEnvironmentId?: string;
    targetService?: string;
    targetServiceId?: string;
    path?: string;
    region?: string;
  };
};

export type TUserOrgInvitedEvent = {
  event: InsightsEventTypes.UserOrgInvitation;
  properties: {
    inviteeEmails: string[];
    projectIds?: string[];
    organizationRoleSlug?: string;
  };
};

export type TTelemetryInstanceStatsEvent = {
  event: InsightsEventTypes.TelemetryInstanceStats;
  properties: {
    users: number;
    identities: number;
    projects: number;
    secrets: number;
    organizations: number;
    organizationNames: number;
    numberOfSecretOperationsMade: number;
    numberOfSecretProcessed: number;
  };
};

export type TSecretRequestCreatedEvent = {
  event: InsightsEventTypes.SecretRequestCreated;
  properties: {
    secretRequestId: string;
    organizationId: string;
    secretRequestName?: string;
  };
};

export type TSecretRequestDeletedEvent = {
  event: InsightsEventTypes.SecretRequestDeleted;
  properties: {
    secretRequestId: string;
    organizationId: string;
  };
};

export type TSignSshKeyEvent = {
  event: InsightsEventTypes.SignSshKey;
  properties: {
    certificateTemplateId: string;
    principals: string[];
    userAgent?: string;
  };
};

export type TIssueSshCredsEvent = {
  event: InsightsEventTypes.IssueSshCreds;
  properties: {
    certificateTemplateId: string;
    principals: string[];
    userAgent?: string;
  };
};

export type TIssueSshHostUserCertEvent = {
  event: InsightsEventTypes.IssueSshHostUserCert;
  properties: {
    sshHostId: string;
    hostname: string;
    principals: string[];
    userAgent?: string;
  };
};

export type TIssueSshHostHostCertEvent = {
  event: InsightsEventTypes.IssueSshHostHostCert;
  properties: {
    sshHostId: string;
    hostname: string;
    principals: string[];
    userAgent?: string;
  };
};

export type TSignCertificateEvent = {
  event: InsightsEventTypes.SignCert;
  properties: {
    caId?: string;
    certificateTemplateId?: string;
    subscriberId?: string;
    commonName: string;
    userAgent?: string;
  };
};

export type TIssueCertificateEvent = {
  event: InsightsEventTypes.IssueCert;
  properties: {
    caId?: string;
    certificateTemplateId?: string;
    subscriberId?: string;
    commonName: string;
    userAgent?: string;
  };
};

export type TInvalidateCacheEvent = {
  event: InsightsEventTypes.InvalidateCache;
  properties: {
    userAgent?: string;
  };
};

export type TNotificationUpdatedEvent = {
  event: InsightsEventTypes.NotificationUpdated;
  properties: {
    notificationId: string;
    isRead?: boolean;
  };
};

export type TInsightsEvent = { distinctId: string; organizationId?: string } & (
  | TSecretModifiedEvent
  | TAdminInitEvent
  | TUserSignedUpEvent
  | TSecretScannerEvent
  | TUserOrgInvitedEvent
  | TMachineIdentityCreatedEvent
  | TIntegrationCreatedEvent
  | TIntegrationSyncedEvent
  | TIntegrationDeletedEvent
  | TProjectCreateEvent
  | TTelemetryInstanceStatsEvent
  | TSecretRequestCreatedEvent
  | TSecretRequestDeletedEvent
  | TSignSshKeyEvent
  | TIssueSshCredsEvent
  | TIssueSshHostUserCertEvent
  | TIssueSshHostHostCertEvent
  | TSignCertificateEvent
  | TIssueCertificateEvent
  | TInvalidateCacheEvent
  | TNotificationUpdatedEvent
);
