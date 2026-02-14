import { OrgAlertBanner } from "../OrgAlertBanner";

export const RedisBanner = () => {
  return (
    <OrgAlertBanner
      text="Attention: Updated versions of KMS now require Hanzo KV for full functionality."
      link="https://hanzo.ai/docs/kms/self-hosting/configuration/requirements#redis"
    />
  );
};
