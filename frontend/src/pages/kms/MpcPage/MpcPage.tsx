import { faKey, faNetworkWired, faPaperPlane, faPlus, faWallet } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import {
  Button,
  Card,
  CardBody,
  CardTitle,
  EmptyState,
  Tab,
  TabList,
  TabPanel,
  Tabs
} from "@app/components/v2";
import { useOrganization, useProject } from "@app/context";

import { MpcNodesTab } from "./components/MpcNodesTab";
import { MpcSigningTab } from "./components/MpcSigningTab";
import { MpcWalletsTab } from "./components/MpcWalletsTab";

export const MpcPage = () => {
  const { currentProject } = useProject();
  const { currentOrg } = useOrganization();

  return (
    <div className="container mx-auto pb-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-white">MPC Wallets</h1>
          <p className="mt-1 text-sm text-bunker-300">
            Manage multi-party computation wallets with threshold signing for secure blockchain operations
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-mineshaft-900">
          <CardBody className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-primary-500/10 p-3">
                <FontAwesomeIcon icon={faNetworkWired} className="text-primary-500" />
              </div>
              <div>
                <p className="text-sm text-bunker-300">MPC Nodes</p>
                <p className="text-2xl font-bold text-white">0</p>
              </div>
            </div>
          </CardBody>
        </Card>

        <Card className="bg-mineshaft-900">
          <CardBody className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-green-500/10 p-3">
                <FontAwesomeIcon icon={faWallet} className="text-green-500" />
              </div>
              <div>
                <p className="text-sm text-bunker-300">Active Wallets</p>
                <p className="text-2xl font-bold text-white">0</p>
              </div>
            </div>
          </CardBody>
        </Card>

        <Card className="bg-mineshaft-900">
          <CardBody className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-yellow-500/10 p-3">
                <FontAwesomeIcon icon={faKey} className="text-yellow-500" />
              </div>
              <div>
                <p className="text-sm text-bunker-300">Pending Signatures</p>
                <p className="text-2xl font-bold text-white">0</p>
              </div>
            </div>
          </CardBody>
        </Card>

        <Card className="bg-mineshaft-900">
          <CardBody className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-blue-500/10 p-3">
                <FontAwesomeIcon icon={faPaperPlane} className="text-blue-500" />
              </div>
              <div>
                <p className="text-sm text-bunker-300">Transactions (24h)</p>
                <p className="text-2xl font-bold text-white">0</p>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="wallets">
        <TabList className="mb-6">
          <Tab value="wallets">
            <FontAwesomeIcon icon={faWallet} className="mr-2" />
            Wallets
          </Tab>
          <Tab value="nodes">
            <FontAwesomeIcon icon={faNetworkWired} className="mr-2" />
            MPC Nodes
          </Tab>
          <Tab value="signing">
            <FontAwesomeIcon icon={faKey} className="mr-2" />
            Signing Requests
          </Tab>
        </TabList>

        <TabPanel value="wallets">
          <MpcWalletsTab orgId={currentOrg.id} projectId={currentProject.id} />
        </TabPanel>

        <TabPanel value="nodes">
          <MpcNodesTab orgId={currentOrg.id} />
        </TabPanel>

        <TabPanel value="signing">
          <MpcSigningTab orgId={currentOrg.id} projectId={currentProject.id} />
        </TabPanel>
      </Tabs>
    </div>
  );
};
