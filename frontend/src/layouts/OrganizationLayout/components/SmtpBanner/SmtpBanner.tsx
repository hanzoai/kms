import { DOCS_BASE_URL } from "@app/helpers/brand";

import { OrgAlertBanner } from "../OrgAlertBanner";

export const SmtpBanner = () => {
  return (
    <OrgAlertBanner
      text="Attention: SMTP has not been configured for this instance."
      link={`${DOCS_BASE_URL}/self-hosting/configuration/envars#email-service`}
    />
  );
};
