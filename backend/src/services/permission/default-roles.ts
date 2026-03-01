// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Built-in role definitions for projects and orgs.
// Each built-in role maps to a set of raw CASL rules.

import { RawRuleOf, MongoAbility } from "@casl/ability";

import { OrgMembershipRole, ProjectMembershipRole } from "@app/db/schemas";

import { OrgPermissionActions, OrgPermissionSubjects, OrgPermissionSet } from "./org-permission";
import {
  ProjectPermissionActions,
  ProjectPermissionCmekActions,
  ProjectPermissionMemberActions,
  ProjectPermissionIdentityActions,
  ProjectPermissionGroupActions,
  ProjectPermissionSecretActions,
  ProjectPermissionCertificateActions,
  ProjectPermissionCertificateAuthorityActions,
  ProjectPermissionPkiSubscriberActions,
  ProjectPermissionSshHostActions,
  ProjectPermissionSet,
  ProjectPermissionSub
} from "./project-permission";

// ---------------------------------------------------------------------------
// Project built-in rules
// ---------------------------------------------------------------------------

type ProjectRule = RawRuleOf<MongoAbility<ProjectPermissionSet>>;

const ADMIN_PROJECT_RULES: ProjectRule[] = [
  // All subjects with all CRUD actions
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.Secrets },
  { action: [ProjectPermissionSecretActions.DescribeAndReadValue, ProjectPermissionSecretActions.DescribeSecret, ProjectPermissionSecretActions.ReadValue, ProjectPermissionSecretActions.Create, ProjectPermissionSecretActions.Edit, ProjectPermissionSecretActions.Delete], subject: ProjectPermissionSub.Secrets },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SecretFolders },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SecretImports },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.DynamicSecrets },
  { action: [ProjectPermissionMemberActions.Read, ProjectPermissionMemberActions.Create, ProjectPermissionMemberActions.Edit, ProjectPermissionMemberActions.Delete, ProjectPermissionMemberActions.GrantPrivileges, ProjectPermissionMemberActions.RevokePrivileges], subject: ProjectPermissionSub.Member },
  { action: [ProjectPermissionIdentityActions.Read, ProjectPermissionIdentityActions.Create, ProjectPermissionIdentityActions.Edit, ProjectPermissionIdentityActions.Delete, ProjectPermissionIdentityActions.GrantPrivileges, ProjectPermissionIdentityActions.RevokePrivileges], subject: ProjectPermissionSub.Identity },
  { action: [ProjectPermissionGroupActions.Read, ProjectPermissionGroupActions.Create, ProjectPermissionGroupActions.Edit, ProjectPermissionGroupActions.Delete], subject: ProjectPermissionSub.Groups },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.Role },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.Integrations },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.Webhooks },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.ServiceTokens },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.Settings },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.Environments },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.Tags },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.AuditLogs },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.IpAllowList },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SecretApproval },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SecretRotation },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SecretRollback },
  // PKI
  { action: [ProjectPermissionCertificateAuthorityActions.Read, ProjectPermissionCertificateAuthorityActions.Create, ProjectPermissionCertificateAuthorityActions.Edit, ProjectPermissionCertificateAuthorityActions.Delete], subject: ProjectPermissionSub.CertificateAuthorities },
  { action: [ProjectPermissionCertificateActions.Read, ProjectPermissionCertificateActions.Create, ProjectPermissionCertificateActions.Edit, ProjectPermissionCertificateActions.Delete, ProjectPermissionCertificateActions.Import], subject: ProjectPermissionSub.Certificates },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.CertificateTemplates },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.PkiAlerts },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.PkiCollections },
  { action: [ProjectPermissionPkiSubscriberActions.Read, ProjectPermissionPkiSubscriberActions.Create, ProjectPermissionPkiSubscriberActions.Edit, ProjectPermissionPkiSubscriberActions.Delete, ProjectPermissionPkiSubscriberActions.IssueCert], subject: ProjectPermissionSub.PkiSubscribers },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.PkiSync },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.PkiTemplates },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.CertificatePolicy },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.CertificateProfile },
  // KMS
  { action: [ProjectPermissionCmekActions.Read, ProjectPermissionCmekActions.Create, ProjectPermissionCmekActions.Edit, ProjectPermissionCmekActions.Delete, ProjectPermissionCmekActions.Encrypt, ProjectPermissionCmekActions.Decrypt, ProjectPermissionCmekActions.Sign, ProjectPermissionCmekActions.Verify, ProjectPermissionCmekActions.ExportPrivateKey], subject: ProjectPermissionSub.Cmek },
  // SSH
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SshCertificateAuthorities },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SshCertificates },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SshCertificateTemplates },
  { action: [ProjectPermissionSshHostActions.Read, ProjectPermissionSshHostActions.Create, ProjectPermissionSshHostActions.Edit, ProjectPermissionSshHostActions.Delete, ProjectPermissionSshHostActions.IssueHostCert], subject: ProjectPermissionSub.SshHosts },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SshHostGroups },
  // Commits / sync / app connections
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Commits },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SecretSync },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.AppConnections }
];

const MEMBER_PROJECT_RULES: ProjectRule[] = [
  { action: [ProjectPermissionSecretActions.DescribeAndReadValue, ProjectPermissionSecretActions.DescribeSecret, ProjectPermissionSecretActions.ReadValue, ProjectPermissionSecretActions.Create, ProjectPermissionSecretActions.Edit, ProjectPermissionSecretActions.Delete], subject: ProjectPermissionSub.Secrets },
  { action: [ProjectPermissionActions.Read, ProjectPermissionActions.Create, ProjectPermissionActions.Edit, ProjectPermissionActions.Delete], subject: ProjectPermissionSub.SecretFolders },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.SecretImports },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.DynamicSecrets },
  { action: [ProjectPermissionMemberActions.Read], subject: ProjectPermissionSub.Member },
  { action: [ProjectPermissionIdentityActions.Read], subject: ProjectPermissionSub.Identity },
  { action: [ProjectPermissionGroupActions.Read], subject: ProjectPermissionSub.Groups },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Role },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Integrations },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Webhooks },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.ServiceTokens },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Settings },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Environments },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Tags },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.AuditLogs },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.IpAllowList },
  { action: [ProjectPermissionCmekActions.Read, ProjectPermissionCmekActions.Encrypt, ProjectPermissionCmekActions.Decrypt, ProjectPermissionCmekActions.Sign, ProjectPermissionCmekActions.Verify], subject: ProjectPermissionSub.Cmek },
  { action: [ProjectPermissionCertificateAuthorityActions.Read], subject: ProjectPermissionSub.CertificateAuthorities },
  { action: [ProjectPermissionCertificateActions.Read], subject: ProjectPermissionSub.Certificates },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.CertificateTemplates }
];

const VIEWER_PROJECT_RULES: ProjectRule[] = [
  { action: [ProjectPermissionSecretActions.DescribeSecret], subject: ProjectPermissionSub.Secrets },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.SecretFolders },
  { action: [ProjectPermissionMemberActions.Read], subject: ProjectPermissionSub.Member },
  { action: [ProjectPermissionIdentityActions.Read], subject: ProjectPermissionSub.Identity },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Role },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Environments },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.Tags },
  { action: [ProjectPermissionCmekActions.Read], subject: ProjectPermissionSub.Cmek }
];

const KMS_CRYPTOGRAPHIC_OPERATOR_RULES: ProjectRule[] = [
  { action: [ProjectPermissionCmekActions.Read, ProjectPermissionCmekActions.Encrypt, ProjectPermissionCmekActions.Decrypt, ProjectPermissionCmekActions.Sign, ProjectPermissionCmekActions.Verify], subject: ProjectPermissionSub.Cmek }
];

// No-access: empty rules array

export const DEFAULT_PROJECT_ROLE_PERMISSIONS: Record<string, ProjectRule[]> = {
  [ProjectMembershipRole.Admin]: ADMIN_PROJECT_RULES,
  [ProjectMembershipRole.Member]: MEMBER_PROJECT_RULES,
  [ProjectMembershipRole.Viewer]: VIEWER_PROJECT_RULES,
  [ProjectMembershipRole.NoAccess]: [],
  [ProjectMembershipRole.KmsCryptographicOperator]: KMS_CRYPTOGRAPHIC_OPERATOR_RULES
};

// ---------------------------------------------------------------------------
// Org built-in rules
// ---------------------------------------------------------------------------

type OrgRule = RawRuleOf<MongoAbility<OrgPermissionSet>>;

const ADMIN_ORG_RULES: OrgRule[] = [
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Workspace },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Role },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Member },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Settings },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.IncidentAccount },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Sso },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Scim },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Ldap },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Groups },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.SecretScanning },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Billing },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Identity },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Kms },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.AuditLogs },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.AppConnections },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Gateway }
];

const MEMBER_ORG_RULES: OrgRule[] = [
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create], subject: OrgPermissionSubjects.Workspace },
  { action: [OrgPermissionActions.Read], subject: OrgPermissionSubjects.Member },
  { action: [OrgPermissionActions.Read], subject: OrgPermissionSubjects.Role },
  { action: [OrgPermissionActions.Read], subject: OrgPermissionSubjects.Groups },
  { action: [OrgPermissionActions.Read], subject: OrgPermissionSubjects.Identity }
];

const NO_ACCESS_ORG_RULES: OrgRule[] = [];

export const DEFAULT_ORG_ROLE_PERMISSIONS: Record<string, OrgRule[]> = {
  [OrgMembershipRole.Admin]: ADMIN_ORG_RULES,
  [OrgMembershipRole.Member]: MEMBER_ORG_RULES,
  [OrgMembershipRole.NoAccess]: NO_ACCESS_ORG_RULES
};

// Named exports expected by project-role-factory and other consumers
export const projectAdminPermissions = ADMIN_PROJECT_RULES;
export const projectMemberPermissions = MEMBER_PROJECT_RULES;
export const projectViewerPermission = VIEWER_PROJECT_RULES;
export const projectNoAccessPermissions: ProjectRule[] = [];
export const cryptographicOperatorPermissions = KMS_CRYPTOGRAPHIC_OPERATOR_RULES;
// SSH host bootstrapper: read-only on SSH hosts and SSH CAs
export const sshHostBootstrapPermissions: ProjectRule[] = [
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.SshHosts },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.SshCertificateAuthorities },
  { action: [ProjectPermissionActions.Read], subject: ProjectPermissionSub.SshCertificateTemplates }
];
