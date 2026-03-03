// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Org-level RBAC permission subjects and actions.

import { RawRuleOf, MongoAbility } from "@casl/ability";

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

// Serialised CASL rule arrays for built-in org roles.
// Exported here because org-role-factory imports them from this module.
type OrgRule = RawRuleOf<MongoAbility<OrgPermissionSet>>;

export const orgAdminPermissions: OrgRule[] = [
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Workspace },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Role },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Member },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Settings },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.IncidentAccount },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Sso },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Scim },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Ldap },
  { action: [OrgPermissionGroupActions.Read, OrgPermissionGroupActions.Create, OrgPermissionGroupActions.Edit, OrgPermissionGroupActions.Delete, OrgPermissionGroupActions.AddMembers, OrgPermissionGroupActions.RemoveMembers, OrgPermissionGroupActions.GrantPrivileges, OrgPermissionGroupActions.RevokePrivileges], subject: OrgPermissionSubjects.Groups },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.SecretScanning },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Billing },
  { action: [OrgPermissionIdentityActions.Read, OrgPermissionIdentityActions.Create, OrgPermissionIdentityActions.Edit, OrgPermissionIdentityActions.Delete, OrgPermissionIdentityActions.GrantPrivileges, OrgPermissionIdentityActions.RevokePrivileges], subject: OrgPermissionSubjects.Identity },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.Kms },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.AuditLogs },
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create, OrgPermissionActions.Edit, OrgPermissionActions.Delete], subject: OrgPermissionSubjects.AppConnections },
  { action: [OrgPermissionGatewayActions.ListGateways, OrgPermissionGatewayActions.CreateGateways, OrgPermissionGatewayActions.DeleteGateways, OrgPermissionGatewayActions.EditGateways, OrgPermissionGatewayActions.AttachGateways], subject: OrgPermissionSubjects.Gateway }
];

export const orgMemberPermissions: OrgRule[] = [
  { action: [OrgPermissionActions.Read, OrgPermissionActions.Create], subject: OrgPermissionSubjects.Workspace },
  { action: [OrgPermissionActions.Read], subject: OrgPermissionSubjects.Member },
  { action: [OrgPermissionActions.Read], subject: OrgPermissionSubjects.Role },
  { action: [OrgPermissionActions.Read], subject: OrgPermissionSubjects.Groups },
  { action: [OrgPermissionActions.Read], subject: OrgPermissionSubjects.Identity }
];

export const orgNoAccessPermissions: OrgRule[] = [];
