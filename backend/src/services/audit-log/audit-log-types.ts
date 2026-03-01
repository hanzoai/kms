// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT

import { ActorType } from "@app/services/auth/auth-type";

export enum UserAgentType {
  WEB = "web",
  CLI = "cli",
  K8_OPERATOR = "k8-operator",
  TERRAFORM = "terraform",
  NODE_SDK = "InfisicalNodeSDK",
  PYTHON_SDK = "InfisicalPythonSDK",
  OTHER = "other"
}

// Exhaustive set of event types for audit logging.
// Add new events here as the system grows.
export enum EventType {
  // Auth
  LOGIN_SUCCESS = "login-success",
  LOGIN_FAILURE = "login-failure",
  LOGOUT = "logout",
  USER_LOGIN = "user-login",
  SELECT_ORGANIZATION = "select-organization",
  SELECT_SUB_ORGANIZATION = "select-sub-organization",
  ORG_ADMIN_BYPASS_SSO = "org-admin-bypass-sso",

  // Users
  GET_USER = "get-user",
  CREATE_USER = "create-user",
  UPDATE_USER = "update-user",
  DELETE_USER = "delete-user",

  // Organizations
  GET_ORG = "get-org",
  CREATE_ORG = "create-org",
  UPDATE_ORG = "update-org",
  DELETE_ORG = "delete-org",

  // Org memberships
  GET_ORG_MEMBERSHIP = "get-org-membership",
  CREATE_ORG_MEMBERSHIP = "create-org-membership",
  UPDATE_ORG_MEMBERSHIP = "update-org-membership",
  DELETE_ORG_MEMBERSHIP = "delete-org-membership",
  INVITE_ORG_MEMBER = "invite-org-member",

  // Projects / workspaces
  GET_PROJECT = "get-project",
  CREATE_PROJECT = "create-project",
  UPDATE_PROJECT = "update-project",
  DELETE_PROJECT = "delete-project",

  // Project memberships
  GET_PROJECT_MEMBERSHIP = "get-project-membership",
  CREATE_PROJECT_MEMBERSHIP = "create-project-membership",
  UPDATE_PROJECT_MEMBERSHIP = "update-project-membership",
  DELETE_PROJECT_MEMBERSHIP = "delete-project-membership",

  // Project environments
  CREATE_ENVIRONMENT = "create-environment",
  UPDATE_ENVIRONMENT = "update-environment",
  DELETE_ENVIRONMENT = "delete-environment",

  // Secrets
  GET_SECRET = "get-secret",
  CREATE_SECRET = "create-secret",
  UPDATE_SECRET = "update-secret",
  DELETE_SECRET = "delete-secret",
  GET_SECRETS = "get-secrets",

  // Secret folders
  CREATE_FOLDER = "create-folder",
  UPDATE_FOLDER = "update-folder",
  DELETE_FOLDER = "delete-folder",

  // Secret imports
  CREATE_SECRET_IMPORT = "create-secret-import",
  UPDATE_SECRET_IMPORT = "update-secret-import",
  DELETE_SECRET_IMPORT = "delete-secret-import",

  // Integrations
  CREATE_INTEGRATION = "create-integration",
  UPDATE_INTEGRATION = "update-integration",
  DELETE_INTEGRATION = "delete-integration",

  // Integration auths
  CREATE_INTEGRATION_AUTH = "create-integration-auth",
  DELETE_INTEGRATION_AUTH = "delete-integration-auth",

  // Service tokens
  CREATE_SERVICE_TOKEN = "create-service-token",
  DELETE_SERVICE_TOKEN = "delete-service-token",

  // API keys
  CREATE_API_KEY = "create-api-key",
  DELETE_API_KEY = "delete-api-key",

  // Identities
  CREATE_IDENTITY = "create-identity",
  UPDATE_IDENTITY = "update-identity",
  DELETE_IDENTITY = "delete-identity",

  // Identity project memberships
  CREATE_IDENTITY_PROJECT_MEMBERSHIP = "create-identity-project-membership",
  UPDATE_IDENTITY_PROJECT_MEMBERSHIP = "update-identity-project-membership",
  DELETE_IDENTITY_PROJECT_MEMBERSHIP = "delete-identity-project-membership",

  // Identity auth
  CREATE_IDENTITY_TOKEN_AUTH = "create-identity-token-auth",
  UPDATE_IDENTITY_TOKEN_AUTH = "update-identity-token-auth",
  DELETE_IDENTITY_TOKEN_AUTH = "delete-identity-token-auth",
  CREATE_TOKEN_IDENTITY_TOKEN_AUTH = "create-token-identity-token-auth",
  DELETE_TOKEN_IDENTITY_TOKEN_AUTH = "delete-token-identity-token-auth",
  GET_TOKENS_IDENTITY_TOKEN_AUTH = "get-tokens-identity-token-auth",
  UPDATE_TOKEN_IDENTITY_TOKEN_AUTH = "update-token-identity-token-auth",

  CREATE_IDENTITY_UNIVERSAL_AUTH = "create-identity-universal-auth",
  UPDATE_IDENTITY_UNIVERSAL_AUTH = "update-identity-universal-auth",
  GET_IDENTITY_UNIVERSAL_AUTH = "get-identity-universal-auth",
  DELETE_IDENTITY_UNIVERSAL_AUTH = "delete-identity-universal-auth",
  CREATE_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRET = "create-identity-universal-auth-client-secret",
  DELETE_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRET = "delete-identity-universal-auth-client-secret",
  GET_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRETS = "get-identity-universal-auth-client-secrets",
  REVOKE_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRET = "revoke-identity-universal-auth-client-secret",

  CREATE_IDENTITY_KUBERNETES_AUTH = "create-identity-kubernetes-auth",
  UPDATE_IDENTITY_KUBERNETES_AUTH = "update-identity-kubernetes-auth",
  DELETE_IDENTITY_KUBERNETES_AUTH = "delete-identity-kubernetes-auth",

  CREATE_IDENTITY_GCP_AUTH = "create-identity-gcp-auth",
  UPDATE_IDENTITY_GCP_AUTH = "update-identity-gcp-auth",
  DELETE_IDENTITY_GCP_AUTH = "delete-identity-gcp-auth",

  CREATE_IDENTITY_AWS_AUTH = "create-identity-aws-auth",
  UPDATE_IDENTITY_AWS_AUTH = "update-identity-aws-auth",
  DELETE_IDENTITY_AWS_AUTH = "delete-identity-aws-auth",

  CREATE_IDENTITY_AZURE_AUTH = "create-identity-azure-auth",
  UPDATE_IDENTITY_AZURE_AUTH = "update-identity-azure-auth",
  DELETE_IDENTITY_AZURE_AUTH = "delete-identity-azure-auth",

  CREATE_IDENTITY_OIDC_AUTH = "create-identity-oidc-auth",
  UPDATE_IDENTITY_OIDC_AUTH = "update-identity-oidc-auth",
  DELETE_IDENTITY_OIDC_AUTH = "delete-identity-oidc-auth",

  CREATE_IDENTITY_JWT_AUTH = "create-identity-jwt-auth",
  UPDATE_IDENTITY_JWT_AUTH = "update-identity-jwt-auth",
  DELETE_IDENTITY_JWT_AUTH = "delete-identity-jwt-auth",

  CREATE_IDENTITY_LDAP_AUTH = "create-identity-ldap-auth",
  UPDATE_IDENTITY_LDAP_AUTH = "update-identity-ldap-auth",
  DELETE_IDENTITY_LDAP_AUTH = "delete-identity-ldap-auth",

  CREATE_IDENTITY_ALICLOUD_AUTH = "create-identity-alicloud-auth",
  UPDATE_IDENTITY_ALICLOUD_AUTH = "update-identity-alicloud-auth",
  DELETE_IDENTITY_ALICLOUD_AUTH = "delete-identity-alicloud-auth",

  CREATE_IDENTITY_OCI_AUTH = "create-identity-oci-auth",
  UPDATE_IDENTITY_OCI_AUTH = "update-identity-oci-auth",
  DELETE_IDENTITY_OCI_AUTH = "delete-identity-oci-auth",

  CREATE_IDENTITY_TLS_CERT_AUTH = "create-identity-tls-cert-auth",
  UPDATE_IDENTITY_TLS_CERT_AUTH = "update-identity-tls-cert-auth",
  DELETE_IDENTITY_TLS_CERT_AUTH = "delete-identity-tls-cert-auth",

  // Roles
  CREATE_ROLE = "create-role",
  UPDATE_ROLE = "update-role",
  DELETE_ROLE = "delete-role",

  // Webhooks
  CREATE_WEBHOOK = "create-webhook",
  UPDATE_WEBHOOK = "update-webhook",
  DELETE_WEBHOOK = "delete-webhook",

  // PKI / certificates
  CREATE_CA = "create-ca",
  GET_CA = "get-ca",
  UPDATE_CA = "update-ca",
  DELETE_CA = "delete-ca",
  SIGN_INTERMEDIATE = "sign-intermediate",
  IMPORT_CA_CERT = "import-ca-cert",
  GET_CA_CSR = "get-ca-csr",
  GET_CA_CERT = "get-ca-cert",
  GET_CA_CRLS = "get-ca-crls",
  GET_CA_CERT_BY_ID = "get-ca-cert-by-id",
  GET_CA_CERTS = "get-ca-certs",
  ISSUE_CERT = "issue-cert",
  SIGN_CERT = "sign-cert",
  DELETE_CERT = "delete-cert",
  REVOKE_CERT = "revoke-cert",
  GET_CERT = "get-cert",
  GET_CERT_BODY = "get-cert-body",

  CREATE_PKI_ALERT = "create-pki-alert",
  UPDATE_PKI_ALERT = "update-pki-alert",
  DELETE_PKI_ALERT = "delete-pki-alert",

  CREATE_PKI_COLLECTION = "create-pki-collection",
  UPDATE_PKI_COLLECTION = "update-pki-collection",
  DELETE_PKI_COLLECTION = "delete-pki-collection",
  ADD_PKI_COLLECTION_ITEM = "add-pki-collection-item",
  DELETE_PKI_COLLECTION_ITEM = "delete-pki-collection-item",

  // KMS (CMEK)
  CREATE_KMS_KEY = "create-kms-key",
  UPDATE_KMS_KEY = "update-kms-key",
  DELETE_KMS_KEY = "delete-kms-key",
  GET_KMS_KEYS = "get-kms-keys",
  GET_KMS_KEY = "get-kms-key",
  CMEK_ENCRYPT = "cmek-encrypt",
  CMEK_DECRYPT = "cmek-decrypt",
  CMEK_SIGN = "cmek-sign",
  CMEK_VERIFY = "cmek-verify",

  // Secret sharing
  READ_SECRET_SHARING = "read-secret-sharing",
  CREATE_SECRET_SHARING = "create-secret-sharing",
  DELETE_SECRET_SHARING = "delete-secret-sharing",

  // Access token
  CREATE_ACCESS_TOKEN = "create-access-token",
  REVOKE_ACCESS_TOKEN = "revoke-access-token",
  RENEW_ACCESS_TOKEN = "renew-access-token",

  // Secret approval
  CREATE_SECRET_APPROVAL_REQUEST = "create-secret-approval-request",
  UPDATE_SECRET_APPROVAL_REQUEST = "update-secret-approval-request",
  MERGE_SECRET_APPROVAL_REQUEST = "merge-secret-approval-request",

  // Secret rotation
  CREATE_SECRET_ROTATION = "create-secret-rotation",
  GET_SECRET_ROTATION = "get-secret-rotation",
  DELETE_SECRET_ROTATION = "delete-secret-rotation",
  RESTART_SECRET_ROTATION = "restart-secret-rotation",

  // Dynamic secrets
  CREATE_DYNAMIC_SECRET = "create-dynamic-secret",
  UPDATE_DYNAMIC_SECRET = "update-dynamic-secret",
  DELETE_DYNAMIC_SECRET = "delete-dynamic-secret",
  LEASE_DYNAMIC_SECRET = "lease-dynamic-secret",
  RENEW_DYNAMIC_SECRET_LEASE = "renew-dynamic-secret-lease",
  REVOKE_DYNAMIC_SECRET_LEASE = "revoke-dynamic-secret-lease",

  // SSH
  CREATE_SSH_CA = "create-ssh-ca",
  GET_SSH_CA = "get-ssh-ca",
  UPDATE_SSH_CA = "update-ssh-ca",
  DELETE_SSH_CA = "delete-ssh-ca",
  GET_SSH_CA_PUBLIC_KEY = "get-ssh-ca-public-key",

  ISSUE_SSH_CREDS = "issue-ssh-creds",
  SIGN_SSH_KEY = "sign-ssh-key",

  // MFA
  UPDATE_USER_AUTH_METHODS = "update-user-auth-methods",

  // TOTP
  CREATE_TOTP_CONFIG = "create-totp-config",
  VERIFY_TOTP = "verify-totp",
  DELETE_TOTP_CONFIG = "delete-totp-config",

  // Misc
  GET_AUDIT_LOGS = "get-audit-logs",
  GET_PROJECT_AUDIT_LOGS = "get-project-audit-logs",
  GET_ORG_AUDIT_LOGS = "get-org-audit-logs"
}

export type Actor = {
  type: ActorType;
  metadata: Record<string, unknown>;
};

export type TCreateAuditLogDTO = {
  actor: Actor;
  orgId?: string;
  projectId?: string;
  event: {
    type: EventType;
    metadata?: Record<string, unknown>;
  };
  ipAddress?: string;
  userAgent?: string;
  userAgentType?: UserAgentType;
};

// Re-export from service to keep fastify.d.ts import working.
export type { TAuditLogServiceFactory } from "./audit-log-service";
