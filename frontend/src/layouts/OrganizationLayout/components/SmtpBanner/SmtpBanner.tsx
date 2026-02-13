import { OrgAlertBanner } from "../OrgAlertBanner";

export const SmtpBanner = () => {
  return (
    <OrgAlertBanner
      text="Attention: SMTP has not been configured for this instance."
      link="https://kms.hanzo.ai/docs/self-hosting/configuration/envars#email-service"
    />
  );
};
