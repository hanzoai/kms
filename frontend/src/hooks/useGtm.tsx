import { useEffect } from "react";
import { Helmet } from "react-helmet";

const GTM_ID = "GTM-WL5C7MWT";
const GTM_SCRIPT_ID = "gtm-script";
const GTM_NOSCRIPT_ID = "gtm-noscript";

const CLOUD_HOSTNAMES = ["kms.hanzo.ai", "us.kms.hanzo.ai", "eu.kms.hanzo.ai"];

const isCloudHostname = () => CLOUD_HOSTNAMES.includes(window.location.hostname);

/**
 * Loads GTM only on Hanzo KMS Cloud pre-auth pages.
 * Cleans up GTM scripts on unmount (when navigating to authenticated pages).
 */
export const useGtm = () => {
  useEffect(() => {
    if (!isCloudHostname()) return undefined;

    // Inject GTM script
    const script = document.createElement("script");
    script.id = GTM_SCRIPT_ID;
    script.async = true;
    script.src = `https://www.googletagmanager.com/gtm.js?id=${GTM_ID}`;
    document.head.appendChild(script);

    // Inject noscript iframe
    const noscript = document.createElement("noscript");
    noscript.id = GTM_NOSCRIPT_ID;
    const iframe = document.createElement("iframe");
    iframe.src = `https://www.googletagmanager.com/ns.html?id=${GTM_ID}`;
    iframe.height = "0";
    iframe.width = "0";
    iframe.style.display = "none";
    iframe.style.visibility = "hidden";
    noscript.appendChild(iframe);
    document.body.insertBefore(noscript, document.body.firstChild);

    return () => {
      document.getElementById(GTM_SCRIPT_ID)?.remove();
      document.getElementById(GTM_NOSCRIPT_ID)?.remove();
    };
  }, []);
};

export const GtmHead = () => {
  const shouldLoad = isCloudHostname();

  useEffect(() => {
    if (!shouldLoad) return undefined;

    const noscript = document.createElement("noscript");
    noscript.id = `${GTM_NOSCRIPT_ID}-head`;
    const iframe = document.createElement("iframe");
    iframe.src = `https://www.googletagmanager.com/ns.html?id=${GTM_ID}`;
    iframe.height = "0";
    iframe.width = "0";
    iframe.style.display = "none";
    iframe.style.visibility = "hidden";
    noscript.appendChild(iframe);
    document.body.insertBefore(noscript, document.body.firstChild);

    return () => {
      document.getElementById(`${GTM_NOSCRIPT_ID}-head`)?.remove();
    };
  }, [shouldLoad]);

  if (!shouldLoad) return null;

  return (
    <Helmet>
      <script async src={`https://www.googletagmanager.com/gtm.js?id=${GTM_ID}`} />
    </Helmet>
  );
};
