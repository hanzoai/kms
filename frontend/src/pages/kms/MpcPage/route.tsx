import { createFileRoute } from "@tanstack/react-router";

import { MpcPage } from "./MpcPage";

export const Route = createFileRoute(
  "/_authenticate/_inject-org-details/_org-layout/organizations/$orgId/projects/kms/$projectId/_kms-layout/mpc"
)({
  component: MpcPage,
  beforeLoad: ({ context }) => {
    return {
      breadcrumbs: [
        ...context.breadcrumbs,
        {
          label: "MPC Wallets"
        }
      ]
    };
  }
});
