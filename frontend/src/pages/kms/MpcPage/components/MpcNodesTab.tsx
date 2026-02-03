import { useState } from "react";
import {
  faCircle,
  faEllipsis,
  faNetworkWired,
  faPencil,
  faPlus,
  faRefresh,
  faTrash
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  EmptyState,
  Table,
  TableContainer,
  TBody,
  Td,
  Th,
  THead,
  Tr
} from "@app/components/v2";

import { AddNodeModal } from "./AddNodeModal";

interface MpcNodesTabProps {
  orgId: string;
}

// Mock data for demonstration
const mockNodes = [
  {
    id: "1",
    name: "Primary Node",
    nodeId: "node_primary_1",
    endpoint: "https://mpc1.example.com",
    port: 8080,
    status: "online",
    lastSeen: new Date().toISOString(),
    metadata: {
      version: "1.0.4",
      uptime: 864000
    }
  },
  {
    id: "2",
    name: "Secondary Node",
    nodeId: "node_secondary_2",
    endpoint: "https://mpc2.example.com",
    port: 8080,
    status: "online",
    lastSeen: new Date().toISOString(),
    metadata: {
      version: "1.0.4",
      uptime: 432000
    }
  },
  {
    id: "3",
    name: "Backup Node",
    nodeId: "node_backup_3",
    endpoint: "https://mpc3.example.com",
    port: 8080,
    status: "offline",
    lastSeen: new Date(Date.now() - 3600000).toISOString(),
    metadata: {
      version: "1.0.3",
      uptime: 0
    }
  }
];

export const MpcNodesTab = ({ orgId }: MpcNodesTabProps) => {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [nodes] = useState(mockNodes);

  const getStatusIndicator = (status: string) => {
    const statusColors: Record<string, string> = {
      online: "text-green-500",
      offline: "text-gray-500",
      syncing: "text-yellow-500",
      error: "text-red-500"
    };

    return (
      <div className="flex items-center gap-2">
        <FontAwesomeIcon
          icon={faCircle}
          className={`h-2 w-2 ${statusColors[status] || statusColors.offline}`}
        />
        <span className="capitalize text-bunker-200">{status}</span>
      </div>
    );
  };

  const formatUptime = (seconds: number) => {
    if (seconds === 0) return "—";
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    if (days > 0) return `${days}d ${hours}h`;
    return `${hours}h`;
  };

  const formatLastSeen = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium text-white">MPC Nodes</h2>
          <p className="text-sm text-bunker-400">
            Manage the nodes that participate in threshold signing operations
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline_bg"
            leftIcon={<FontAwesomeIcon icon={faRefresh} />}
            colorSchema="secondary"
          >
            Refresh Status
          </Button>
          <Button
            leftIcon={<FontAwesomeIcon icon={faPlus} />}
            colorSchema="primary"
            onClick={() => setIsAddModalOpen(true)}
          >
            Add Node
          </Button>
        </div>
      </div>

      {nodes.length === 0 ? (
        <EmptyState
          title="No MPC nodes configured"
          icon={faNetworkWired}
        >
          <p className="mb-4 text-sm text-bunker-300">
            Add MPC nodes to enable threshold signing operations.
          </p>
          <Button
            leftIcon={<FontAwesomeIcon icon={faPlus} />}
            colorSchema="primary"
            onClick={() => setIsAddModalOpen(true)}
          >
            Add Node
          </Button>
        </EmptyState>
      ) : (
        <TableContainer>
          <Table>
            <THead>
              <Tr>
                <Th>Node</Th>
                <Th>Endpoint</Th>
                <Th>Status</Th>
                <Th>Last Seen</Th>
                <Th>Uptime</Th>
                <Th>Version</Th>
                <Th className="w-16" />
              </Tr>
            </THead>
            <TBody>
              {nodes.map((node) => (
                <Tr key={node.id}>
                  <Td>
                    <div className="flex items-center gap-3">
                      <div className="rounded-lg bg-bunker-700 p-2">
                        <FontAwesomeIcon icon={faNetworkWired} className="text-bunker-300" />
                      </div>
                      <div>
                        <p className="font-medium text-white">{node.name}</p>
                        <p className="text-xs text-bunker-400">{node.nodeId}</p>
                      </div>
                    </div>
                  </Td>
                  <Td>
                    <span className="text-sm text-bunker-200">
                      {node.endpoint}:{node.port}
                    </span>
                  </Td>
                  <Td>{getStatusIndicator(node.status)}</Td>
                  <Td>
                    <span className="text-sm text-bunker-300">
                      {formatLastSeen(node.lastSeen)}
                    </span>
                  </Td>
                  <Td>
                    <span className="text-sm text-bunker-300">
                      {formatUptime(node.metadata.uptime)}
                    </span>
                  </Td>
                  <Td>
                    <span className="rounded bg-bunker-700 px-2 py-1 text-xs text-bunker-200">
                      v{node.metadata.version}
                    </span>
                  </Td>
                  <Td>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="plain" colorSchema="secondary" size="xs">
                          <FontAwesomeIcon icon={faEllipsis} />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem icon={<FontAwesomeIcon icon={faPencil} />}>
                          Edit Node
                        </DropdownMenuItem>
                        <DropdownMenuItem icon={<FontAwesomeIcon icon={faRefresh} />}>
                          Check Health
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          icon={<FontAwesomeIcon icon={faTrash} />}
                          className="text-red-500"
                        >
                          Remove Node
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        </TableContainer>
      )}

      <AddNodeModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        orgId={orgId}
      />
    </div>
  );
};
