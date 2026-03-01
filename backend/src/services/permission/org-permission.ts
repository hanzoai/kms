// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Org-level RBAC permission subjects and actions.

export enum OrgPermissionActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum OrgPermissionIdentityActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  GrantPrivileges = "grant-privileges",
  RevokePrivileges = "revoke-privileges"
}

export enum OrgPermissionGroupActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete",
  AddMembers = "add-members",
  RemoveMembers = "remove-members",
  GrantPrivileges = "grant-privileges",
  RevokePrivileges = "revoke-privileges"
}

export enum OrgPermissionAdminConsoleAction {
  AccessAllProjects = "access-all-projects"
}

export enum OrgPermissionAppConnectionActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

export enum OrgPermissionGatewayActions {
  ListGateways = "list-gateways",
  CreateGateways = "create-gateways",
  DeleteGateways = "delete-gateways",
  EditGateways = "edit-gateways",
  AttachGateways = "attach-gateways"
}

export enum OrgPermissionSecretShareAction {
  ManageSettings = "manage-settings"
}

export enum OrgPermissionSubOrgActions {
  Create = "create"
}

export enum OrgPermissionMachineIdentityAuthTemplateActions {
  Read = "read",
  Create = "create",
  Edit = "edit",
  Delete = "delete"
}

// Union of all org permission subjects
export enum OrgPermissionSubjects {
  Workspace = "workspace",
  Role = "role",
  Member = "member",
  Settings = "settings",
  IncidentAccount = "incident-account",
  Sso = "sso",
  Scim = "scim",
  Ldap = "ldap",
  Groups = "groups",
  SecretScanning = "secret-scanning",
  Billing = "billing",
  Identity = "identity",
  Kms = "kms",
  AuditLogs = "audit-logs",
  AppConnections = "app-connections",
  Gateway = "gateway",
  AdminConsole = "admin-console",
  SecretShare = "secret-share",
  SubOrg = "sub-org",
  MachineIdentityAuthTemplates = "machine-identity-auth-templates"
}

// OrgPermissionSet: all possible [action, subject] tuples for CASL
export type OrgPermissionSet =
  | [OrgPermissionActions, OrgPermissionSubjects.Workspace]
  | [OrgPermissionActions, OrgPermissionSubjects.Role]
  | [OrgPermissionActions, OrgPermissionSubjects.Member]
  | [OrgPermissionActions, OrgPermissionSubjects.Settings]
  | [OrgPermissionActions, OrgPermissionSubjects.IncidentAccount]
  | [OrgPermissionActions, OrgPermissionSubjects.Sso]
  | [OrgPermissionActions, OrgPermissionSubjects.Scim]
  | [OrgPermissionActions, OrgPermissionSubjects.Ldap]
  | [OrgPermissionGroupActions, OrgPermissionSubjects.Groups]
  | [OrgPermissionActions, OrgPermissionSubjects.SecretScanning]
  | [OrgPermissionActions, OrgPermissionSubjects.Billing]
  | [OrgPermissionIdentityActions, OrgPermissionSubjects.Identity]
  | [OrgPermissionActions, OrgPermissionSubjects.Kms]
  | [OrgPermissionActions, OrgPermissionSubjects.AuditLogs]
  | [OrgPermissionAppConnectionActions, OrgPermissionSubjects.AppConnections]
  | [OrgPermissionGatewayActions, OrgPermissionSubjects.Gateway]
  | [OrgPermissionAdminConsoleAction, OrgPermissionSubjects.AdminConsole]
  | [OrgPermissionSecretShareAction, OrgPermissionSubjects.SecretShare]
  | [OrgPermissionSubOrgActions, OrgPermissionSubjects.SubOrg]
  | [OrgPermissionMachineIdentityAuthTemplateActions, OrgPermissionSubjects.MachineIdentityAuthTemplates];
