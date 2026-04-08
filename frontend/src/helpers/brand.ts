const getMetaContent = (name: string): string =>
  document.querySelector(`meta[name="${name}"]`)?.getAttribute("content") ?? "";

export const SITE_NAME = getMetaContent("site-name") || "KMS";
export const SUPPORT_EMAIL = getMetaContent("support-email") || "";
export const DOCS_BASE_URL = getMetaContent("docs-url") || "/docs";
export const SLACK_URL = getMetaContent("slack-url") || "";
export const SITE_URL = getMetaContent("site-url") || "";

export const docsUrl = (path: string): string => `${DOCS_BASE_URL}${path}`;
