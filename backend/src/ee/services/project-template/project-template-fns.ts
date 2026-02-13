import { ProjectType } from "@app/db/schemas";
import {
  KmsProjectTemplate,
  TUnpackedPermission
} from "@app/ee/services/project-template/project-template-types";
import { getPredefinedRoles } from "@app/services/project-role/project-role-fns";

import { ProjectTemplateDefaultEnvironments } from "./project-template-constants";

export const getDefaultProjectTemplate = (orgId: string, type: ProjectType) => ({
  id: "b11b49a9-09a9-4443-916a-4246f9ff2c69", // random ID to appease zod
  type,
  name: KmsProjectTemplate.Default,
  createdAt: new Date(),
  updatedAt: new Date(),
  description: `KMS's ${type} default project template`,
  environments: type === ProjectType.SecretManager ? ProjectTemplateDefaultEnvironments : null,
  roles: [...getPredefinedRoles({ projectId: "project-template", projectType: type })].map(
    ({ name, slug, permissions }) => ({
      name,
      slug,
      permissions: permissions as TUnpackedPermission[]
    })
  ),
  users: null,
  groups: null,
  identities: null,
  projectManagedIdentities: null,
  orgId
});

export const isKmsProjectTemplate = (template: string) =>
  Object.values(KmsProjectTemplate).includes(template as KmsProjectTemplate);
