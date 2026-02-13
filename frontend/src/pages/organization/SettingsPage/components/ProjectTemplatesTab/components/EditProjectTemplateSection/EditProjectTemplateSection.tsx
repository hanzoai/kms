import { faChevronLeft } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import { Button, EmptyState, Spinner } from "@app/components/v2";
import {
  KmsProjectTemplate,
  TProjectTemplate,
  useGetProjectTemplateById
} from "@app/hooks/api/projectTemplates";

import { EditProjectTemplate } from "./components";

type Props = {
  template: TProjectTemplate;
  onBack: () => void;
};

export const EditProjectTemplateSection = ({ template, onBack }: Props) => {
  const isKmsTemplate = Object.values(KmsProjectTemplate).includes(
    template.name as KmsProjectTemplate
  );

  const { data: projectTemplate, isPending } = useGetProjectTemplateById(template.id, {
    initialData: template,
    enabled: !isKmsTemplate
  });
  const finalTemplate = isKmsTemplate ? template : projectTemplate;

  return (
    <div>
      <Button
        variant="link"
        type="submit"
        leftIcon={<FontAwesomeIcon icon={faChevronLeft} />}
        onClick={onBack}
        className="mb-4"
      >
        Back to Templates
      </Button>
      {/* eslint-disable-next-line no-nested-ternary */}
      {isPending ? (
        <div className="flex h-[60vh] w-full items-center justify-center p-24">
          <Spinner />
        </div>
      ) : finalTemplate ? (
        <EditProjectTemplate
          isKmsTemplate={isKmsTemplate}
          projectTemplate={finalTemplate}
          onBack={onBack}
        />
      ) : (
        <EmptyState title="Error: Unable to find project template." className="py-12" />
      )}
    </div>
  );
};
