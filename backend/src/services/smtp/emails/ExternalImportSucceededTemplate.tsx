import { Heading, Section, Text } from "@react-email/components";
import React from "react";

import { BaseEmailWrapper, BaseEmailWrapperProps } from "./BaseEmailWrapper";

interface ExternalImportSucceededTemplateProps extends Omit<BaseEmailWrapperProps, "title" | "preview" | "children"> {
  provider: string;
}

export const ExternalImportSucceededTemplate = ({ siteUrl, provider }: ExternalImportSucceededTemplateProps) => {
  return (
    <BaseEmailWrapper title="Import Complete" preview={`An import from ${provider} has completed.`} siteUrl={siteUrl}>
      <Heading className="text-black text-[18px] leading-[28px] text-center font-normal p-0 mx-0">
        An import from <strong>{provider}</strong> to Hanzo KMS has completed
      </Heading>
      <Section className="px-[24px] mt-[36px] pt-[12px] pb-[8px] border border-solid border-gray-200 rounded-md bg-gray-50">
        <Text className="text-black text-[14px] leading-[24px]">
          An import from <strong>{provider}</strong> to Hanzo KMS was successful. Your data is now available in
          Hanzo KMS.
        </Text>
      </Section>
    </BaseEmailWrapper>
  );
};

export default ExternalImportSucceededTemplate;

ExternalImportSucceededTemplate.PreviewProps = {
  provider: "EnvKey",
  siteUrl: "https://kms.hanzo.ai"
} as ExternalImportSucceededTemplateProps;
