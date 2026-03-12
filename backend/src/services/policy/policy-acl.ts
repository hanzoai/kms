import { type ACLCheckResult, Capability, type PathRule, type Policy, type TemplateContext } from "./policy-types";

/**
 * Check if a request path + capability is allowed by a set of policies.
 * Uses longest-prefix matching. Deny always wins.
 */
export function checkPermissions(
  requestPath: string,
  capability: Capability,
  policies: Policy[],
  templateContext?: TemplateContext
): ACLCheckResult {
  let bestMatch: { rule: PathRule; specificity: number } | null = null;

  for (const policy of policies) {
    for (const rule of policy.rules) {
      const resolvedPath = templateContext ? resolveTemplate(rule.path, templateContext) : rule.path;
      const specificity = matchPath(resolvedPath, requestPath);

      if (specificity < 0) continue;
      if (!bestMatch || specificity > bestMatch.specificity) {
        bestMatch = { rule, specificity };
      }
    }
  }

  if (!bestMatch) {
    return { allowed: false, capabilities: [] };
  }

  const { rule } = bestMatch;

  // Deny takes absolute priority
  if (rule.capabilities.includes(Capability.Deny)) {
    return { allowed: false, capabilities: [Capability.Deny], matchedPath: rule.path };
  }

  const allowed = rule.capabilities.includes(capability) || rule.capabilities.includes(Capability.Sudo);

  return {
    allowed,
    capabilities: rule.capabilities,
    matchedPath: rule.path
  };
}

/**
 * Match a pattern against a path. Returns specificity score (higher = more specific)
 * or -1 if no match.
 *
 * Patterns:
 *   "secret/data/foo"   - exact match (highest specificity)
 *   "secret/data/*"     - glob suffix match
 *   "secret/+/foo"      - single segment wildcard
 */
function matchPath(pattern: string, path: string): number {
  // Exact match - highest specificity
  if (pattern === path) return pattern.length * 100;

  // Glob suffix: "foo/bar/*" matches "foo/bar/baz" and "foo/bar/baz/qux"
  if (pattern.endsWith("*")) {
    const prefix = pattern.slice(0, -1);
    if (path.startsWith(prefix)) {
      return prefix.length * 10;
    }
    return -1;
  }

  // Segment wildcard: "foo/+/bar" matches "foo/anything/bar"
  if (pattern.includes("+")) {
    const patternParts = pattern.split("/");
    const pathParts = path.split("/");

    if (patternParts.length !== pathParts.length) return -1;

    let score = 0;
    for (let i = 0; i < patternParts.length; i++) {
      if (patternParts[i] === "+") {
        score += 1; // wildcard segment
      } else if (patternParts[i] === pathParts[i]) {
        score += 10; // exact segment match
      } else {
        return -1; // mismatch
      }
    }
    return score;
  }

  return -1;
}

/**
 * Resolve template variables in a path pattern.
 * e.g. "secret/data/{{identity.org_id}}/*" → "secret/data/org-123/*"
 */
function resolveTemplate(pattern: string, ctx: TemplateContext): string {
  return pattern.replace(/\{\{([^}]+)\}\}/g, (_, key: string) => {
    const value = ctx[key.trim()];
    if (value === undefined) return `{{${key}}}`;
    return value;
  });
}
