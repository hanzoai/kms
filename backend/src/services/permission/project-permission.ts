// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Project-level RBAC permission subjects and actions.

// General CRUD actions used across many subjects
export enum ProjectPermissionActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

// Per-resource action sets

export enum ProjectPermissionSecretActions {
  DescribeAndReadValue = "read",
  DescribeSecret = "describeSecret",
  ReadValue = "readValue",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  Subscribe = "subscribe"
}

export enum ProjectPermissionMemberActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  GrantPrivileges = "grant-privileges",
  RevokePrivileges = "revoke-privileges"
}

export enum ProjectPermissionIdentityActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  GrantPrivileges = "grant-privileges",
  RevokePrivileges = "revoke-privileges"
}

export enum ProjectPermissionGroupActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  GrantPrivileges = "grant-privileges",
  RevokePrivileges = "revoke-privileges"
}

export enum ProjectPermissionCmekActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  Encrypt = "encrypt",
  Decrypt = "decrypt",
  Sign = "sign",
  Verify = "verify",
  ExportPrivateKey = "export-private-key"
}

export enum ProjectPermissionCertificateActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  Import = "import"
}

export enum ProjectPermissionCertificateAuthorityActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum ProjectPermissionCertificatePolicyActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum ProjectPermissionCertificateProfileActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum ProjectPermissionPkiSubscriberActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  IssueCert = "issue-cert"
}

export enum ProjectPermissionPkiSyncActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  SyncCertificates = "sync-certificates"
}

export enum ProjectPermissionPkiTemplateActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum ProjectPermissionSecretSyncActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  SyncSecrets = "sync-secrets",
  ImportSecrets = "import-secrets",
  RemoveSecrets = "remove-secrets"
}

export enum ProjectPermissionCommitsActions {
  Read = "read"
}

export enum ProjectPermissionSshHostActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  IssueHostCert = "issue-host-cert"
}

export enum ProjectPermissionAppConnectionActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum ProjectPermissionApprovalRequestActions {
  Read = "read",
  Create = "create",
  Review = "review"
}

export enum ProjectPermissionApprovalRequestGrantActions {
  Read = "read",
  Create = "create",
  Revoke = "revoke"
}

// Subject (resource type) enum for project permissions
export enum ProjectPermissionSub {
  Role = "role",
  Member = "member",
  Groups = "groups",
  Settings = "project-settings",
  Integrations = "integrations",
  Webhooks = "webhooks",
  ServiceTokens = "service-tokens",
  Environments = "environments",
  Tags = "tags",
  AuditLogs = "audit-logs",
  IpAllowList = "ip-allowlist",
  // Secrets
  Secrets = "secrets",
  SecretFolders = "secret-folders",
  SecretImports = "secret-imports",
  DynamicSecrets = "dynamic-secrets",
  SecretRollback = "secret-rollback",
  SecretApproval = "secret-approval",
  SecretRotation = "secret-rotation",
  // Identity
  Identity = "identity",
  // Certificates / PKI
  CertificateAuthorities = "certificate-authorities",
  Certificates = "certificates",
  CertificateTemplates = "certificate-templates",
  PkiAlerts = "pki-alerts",
  PkiCollections = "pki-collections",
  PkiSubscribers = "pki-subscribers",
  PkiSync = "pki-sync",
  PkiTemplates = "pki-templates",
  CertificatePolicy = "certificate-policy",
  CertificateProfile = "certificate-profile",
  // KMS
  Cmek = "cmek",
  // SSH
  SshCertificateAuthorities = "ssh-certificate-authorities",
  SshCertificates = "ssh-certificates",
  SshCertificateTemplates = "ssh-certificate-templates",
  SshHosts = "ssh-hosts",
  SshHostGroups = "ssh-host-groups",
  // Commit / version tracking
  Commits = "commits",
  // Secret sync
  SecretSync = "secret-sync",
  // App connections
  AppConnections = "app-connections",
  // Approval requests
  ApprovalRequests = "approval-requests",
  ApprovalRequestGrants = "approval-request-grants"
}

// Full set of [action, subject] tuples for CASL MongoAbility
export type ProjectPermissionSet =
  | [ProjectPermissionActions, ProjectPermissionSub.Role]
  | [ProjectPermissionMemberActions, ProjectPermissionSub.Member]
  | [ProjectPermissionGroupActions, ProjectPermissionSub.Groups]
  | [ProjectPermissionActions, ProjectPermissionSub.Settings]
  | [ProjectPermissionActions, ProjectPermissionSub.Integrations]
  | [ProjectPermissionActions, ProjectPermissionSub.Webhooks]
  | [ProjectPermissionActions, ProjectPermissionSub.ServiceTokens]
  | [ProjectPermissionActions, ProjectPermissionSub.Environments]
  | [ProjectPermissionActions, ProjectPermissionSub.Tags]
  | [ProjectPermissionActions, ProjectPermissionSub.AuditLogs]
  | [ProjectPermissionActions, ProjectPermissionSub.IpAllowList]
  | [ProjectPermissionSecretActions, ProjectPermissionSub.Secrets]
  | [ProjectPermissionActions, ProjectPermissionSub.SecretFolders]
  | [ProjectPermissionActions, ProjectPermissionSub.SecretImports]
  | [ProjectPermissionActions, ProjectPermissionSub.DynamicSecrets]
  | [ProjectPermissionActions, ProjectPermissionSub.SecretRollback]
  | [ProjectPermissionActions, ProjectPermissionSub.SecretApproval]
  | [ProjectPermissionActions, ProjectPermissionSub.SecretRotation]
  | [ProjectPermissionIdentityActions, ProjectPermissionSub.Identity]
  | [ProjectPermissionCertificateAuthorityActions, ProjectPermissionSub.CertificateAuthorities]
  | [ProjectPermissionCertificateActions, ProjectPermissionSub.Certificates]
  | [ProjectPermissionActions, ProjectPermissionSub.CertificateTemplates]
  | [ProjectPermissionActions, ProjectPermissionSub.PkiAlerts]
  | [ProjectPermissionActions, ProjectPermissionSub.PkiCollections]
  | [ProjectPermissionPkiSubscriberActions, ProjectPermissionSub.PkiSubscribers]
  | [ProjectPermissionPkiSyncActions, ProjectPermissionSub.PkiSync]
  | [ProjectPermissionPkiTemplateActions, ProjectPermissionSub.PkiTemplates]
  | [ProjectPermissionCertificatePolicyActions, ProjectPermissionSub.CertificatePolicy]
  | [ProjectPermissionCertificateProfileActions, ProjectPermissionSub.CertificateProfile]
  | [ProjectPermissionCmekActions, ProjectPermissionSub.Cmek]
  | [ProjectPermissionActions, ProjectPermissionSub.SshCertificateAuthorities]
  | [ProjectPermissionActions, ProjectPermissionSub.SshCertificates]
  | [ProjectPermissionActions, ProjectPermissionSub.SshCertificateTemplates]
  | [ProjectPermissionSshHostActions, ProjectPermissionSub.SshHosts]
  | [ProjectPermissionActions, ProjectPermissionSub.SshHostGroups]
  | [ProjectPermissionCommitsActions, ProjectPermissionSub.Commits]
  | [ProjectPermissionSecretSyncActions, ProjectPermissionSub.SecretSync]
  | [ProjectPermissionAppConnectionActions, ProjectPermissionSub.AppConnections]
  | [ProjectPermissionApprovalRequestActions, ProjectPermissionSub.ApprovalRequests]
  | [ProjectPermissionApprovalRequestGrantActions, ProjectPermissionSub.ApprovalRequestGrants];

// Helpers

const RESERVED_PROJECT_ROLE_SLUGS = [
  "admin",
  "member",
  "viewer",
  "no-access",
  "cryptographic-operator",
  "ssh-host-bootstrapper"
] as const;

/** Returns true when the role slug is NOT one of the built-in project roles. */
export const isCustomProjectRole = (roleSlug: string): boolean =>
  !RESERVED_PROJECT_ROLE_SLUGS.find((r) => r === roleSlug);
