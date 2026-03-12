export enum Capability {
  Deny = "deny",
  Create = "create",
  Read = "read",
  Update = "update",
  Delete = "delete",
  List = "list",
  Sudo = "sudo",
  Patch = "patch"
}

export interface PathRule {
  path: string;       // glob pattern: "secret/data/*", "transit/encrypt/+"
  capabilities: Capability[];
  allowedParameters?: Record<string, string[]>;
  deniedParameters?: Record<string, string[]>;
  requiredParameters?: string[];
}

export interface Policy {
  name: string;
  rules: PathRule[];
  createdAt: Date;
  updatedAt: Date;
}

export interface PolicyInput {
  name: string;
  path: Record<string, { capabilities: string[]; allowed_parameters?: Record<string, string[]>; denied_parameters?: Record<string, string[]>; required_parameters?: string[] }>;
}

export interface ACLCheckResult {
  allowed: boolean;
  capabilities: Capability[];
  matchedPath?: string;
}

export interface TemplateContext {
  "identity.org_id"?: string;
  "identity.project_id"?: string;
  "identity.entity_id"?: string;
  "identity.name"?: string;
  [key: string]: string | undefined;
}
