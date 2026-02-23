export const publicPaths = [
  "/",
  // `/integrations`,
  "/signupinvite",
  "/pricing",
  "/signup",
  "/signup/sso",
  "/login",
  "/login/ldap",
  "/blog",
  "/docs",
  "/changelog",
  "/security",
  "/scheduledemo",
  "/blog/[slug]",
  "/faq",
  "/privacy",
  "/terms",
  "/subprocessors",
  "/verify-email",
  "/password-reset",
  "/saml-sso",
  "/login/provider/success", // TODO: change
  "/login/provider/error", // TODO: change
  "/login/sso",
  "/admin/signup",
  "/shared/secret/[id]",
  "/secret-request/secret/[id]",
  "/share-secret"
];

export const languageMap = {
  en: "English",
  ko: "한국어",
  fr: "Français"
};

interface Mapping {
  [key: string]: string;
}

const plansDev: Mapping = {
  starter: "prod_Nt6kPvYsVBuzVH",
  team: "prod_NEpD2WMXUS2eDn",
  professional: "prod_Mb4CetZ2jE7jdl",
  enterprise: "licence_key_required"
};

const plansProd: Mapping = {
  starter: "prod_Mb8oR5XNwyFTul",
  team: "prod_NEp7fAB3UJWK6A",
  professional: "prod_Mb8pUIpA0OUi5N",
  enterprise: "licence_key_required"
};

export const plans = plansProd || plansDev;

export const leaveConfirmDefaultMessage =
  "Your changes will be lost if you leave the page. Are you sure you want to continue?";

export enum SessionStorageKeys {
  CLI_TERMINAL_TOKEN = "CLI_TERMINAL_TOKEN",
  ORG_LOGIN_SUCCESS_REDIRECT_URL = "ORG_LOGIN_SUCCESS_REDIRECT_URL",
  AUTH_CONSENT = "AUTH_CONSENT",
  MFA_TEMP_TOKEN = "MFA_TEMP_TOKEN"
}

export const secretTagsColors = [
  {
    id: 1,
    hex: "#bec2c8",
    rgba: "rgb(128,128,128, 0.8)",
    name: "Grey",
    selected: true
  },
  {
    id: 2,
    hex: "#95a2b3",
    rgba: "rgb(128,128,128, 0.8)",
    name: "blue",
    selected: false
  },
  {
    id: 3,
    hex: "#8a8a8a",
    rgba: "rgb(138,138,138, 0.8)",
    name: "Purple",
    selected: false
  },
  {
    id: 4,
    hex: "#737373",
    rgba: "rgb(115,115,115, 0.8)",
    name: "Teal",
    selected: false
  },
  {
    id: 5,
    hex: "#a3a3a3",
    rgba: "rgb(163,163,163, 0.8)",
    name: "Green",
    selected: false
  },
  {
    id: 6,
    hex: "#d4d4d4",
    rgba: "rgb(212,212,212, 0.8)",
    name: "Yellow",
    selected: false
  },
  {
    id: 7,
    hex: "#b3b3b3",
    rgba: "rgb(179,179,179, 0.8)",
    name: "Orange",
    selected: false
  },
  {
    id: 8,
    hex: "#e5e5e5",
    rgba: "rgb(229,229,229, 0.8)",
    name: "Pink",
    selected: false
  },
  {
    id: 9,
    hex: "#525252",
    rgba: "rgb(82,82,82, 0.8)",
    name: "Red",
    selected: false
  }
];
