// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Shared permission helper functions.

import { MongoAbility } from "@casl/ability";
import { ForbiddenRequestError } from "@app/lib/errors";
import { AuthMethod } from "@app/services/auth/auth-type";

import { ProjectPermissionSecretActions, ProjectPermissionSub } from "./project-permission";

// ---------------------------------------------------------------------------
// Auth method helpers
// ---------------------------------------------------------------------------

/** Returns true if the auth method is SAML-based. */
export const isAuthMethodSaml = (authMethod: AuthMethod | null | undefined): boolean => {
  if (!authMethod) return false;
  return [
    AuthMethod.OKTA_SAML,
    AuthMethod.AZURE_SAML,
    AuthMethod.JUMPCLOUD_SAML,
    AuthMethod.GOOGLE_SAML,
    AuthMethod.KEYCLOAK_SAML
  ].includes(authMethod as AuthMethod);
};

// ---------------------------------------------------------------------------
// Secret describe/read helpers
// ---------------------------------------------------------------------------

/**
 * Returns true if the ability can perform the given secret action (action
 * parameter) on the supplied subject/conditions. Supports both the legacy
 * combined DescribeAndReadValue action and the split DescribeSecret/ReadValue
 * system.
 *
 * Three-argument form: (ability, action, subjectOrConditions)
 * Two-argument form (legacy): (ability, subject)
 */
export const hasSecretReadValueOrDescribePermission = (
  ability: MongoAbility,
  actionOrSubject: ProjectPermissionSecretActions | ProjectPermissionSub.Secrets | string,
  subjectOrConditions?: ProjectPermissionSub.Secrets | string | Record<string, unknown>
): boolean => {
  // Two-arg legacy call: (ability, subject)
  if (subjectOrConditions === undefined) {
    const sub = actionOrSubject as ProjectPermissionSub.Secrets;
    return (
      ability.can(ProjectPermissionSecretActions.DescribeAndReadValue, sub) ||
      (ability.can(ProjectPermissionSecretActions.DescribeSecret, sub) &&
        ability.can(ProjectPermissionSecretActions.ReadValue, sub))
    );
  }

  // Three-arg call: (ability, action, subject/conditions)
  const action = actionOrSubject as ProjectPermissionSecretActions;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return ability.can(action, subjectOrConditions as any);
};

/**
 * Throws ForbiddenRequestError unless the ability has secret read-value or
 * describe permission.
 */
export const throwIfMissingSecretReadValueOrDescribePermission = (
  ability: MongoAbility,
  actionOrSubject: ProjectPermissionSecretActions | ProjectPermissionSub.Secrets | string,
  subjectOrConditions?: ProjectPermissionSub.Secrets | string | Record<string, unknown>
): void => {
  if (!hasSecretReadValueOrDescribePermission(ability, actionOrSubject, subjectOrConditions)) {
    throw new ForbiddenRequestError({
      message: "You do not have permission to read secret values"
    });
  }
};

// ---------------------------------------------------------------------------
// Privilege change validation
// ---------------------------------------------------------------------------

export type TPermissionBoundaryResult = {
  isValid: boolean;
  missingPermissions?: string[];
};

/**
 * Validates whether a privilege change operation is allowed given the
 * requestor's permission vs the target's permission.
 *
 * When shouldUseNewPrivilegeSystem is true: the requestor must hold all
 * permissions that the target holds (privilege boundary check).
 * When false (legacy): the check always passes.
 */
export const validatePrivilegeChangeOperation = (
  shouldUseNewPrivilegeSystem: boolean | null | undefined,
  _action: string,
  _subject: string,
  requestorPermission: MongoAbility,
  targetPermission: MongoAbility
): TPermissionBoundaryResult => {
  if (!shouldUseNewPrivilegeSystem) {
    return { isValid: true };
  }

  // Extract rules the target can perform and check if requestor can perform them too.
  const targetRules = targetPermission.rules;
  const missingPermissions: string[] = [];

  for (const rule of targetRules) {
    if (rule.inverted) continue; // skip deny rules
    const actions = Array.isArray(rule.action) ? rule.action : [rule.action];
    const subjects = Array.isArray(rule.subject) ? rule.subject : [rule.subject];
    for (const action of actions) {
      for (const sub of subjects) {
        if (!requestorPermission.can(action as string, sub as string)) {
          missingPermissions.push(`${action}:${sub as string}`);
        }
      }
    }
  }

  return {
    isValid: missingPermissions.length === 0,
    missingPermissions: missingPermissions.length > 0 ? missingPermissions : undefined
  };
};

/**
 * Builds a human-readable error message for a permission boundary failure.
 */
export const constructPermissionErrorMessage = (
  baseMessage: string,
  shouldUseNewPrivilegeSystem: boolean | null | undefined,
  action: string,
  subject: string
): string => {
  if (!shouldUseNewPrivilegeSystem) {
    return `${baseMessage}: missing ${action} on ${subject}`;
  }
  return `${baseMessage}: you cannot grant permissions you do not possess (${action} on ${subject})`;
};
