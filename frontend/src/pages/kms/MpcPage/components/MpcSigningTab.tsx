import { useState } from "react";
import {
  faCheck,
  faCircle,
  faClock,
  faEllipsis,
  faEye,
  faKey,
  faPaperPlane,
  faPlus,
  faTimes,
  faXmark
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

interface MpcSigningTabProps {
  orgId: string;
  projectId: string;
}

// Mock data for demonstration
const mockSigningRequests = [
  {
    id: "1",
    walletName: "Treasury Wallet",
    chain: "ethereum",
    status: "pending",
    requiredApprovals: 2,
    currentApprovals: 1,
    transactionDetails: {
      to: "0x742d35Cc6634C0532925a3b844Bc9e7595f1D123",
      value: "1.5 ETH",
      type: "Transfer"
    },
    initiator: "admin@example.com",
    createdAt: new Date(Date.now() - 3600000).toISOString(),
    expiresAt: new Date(Date.now() + 82800000).toISOString()
  },
  {
    id: "2",
    walletName: "Operations Wallet",
    chain: "bitcoin",
    status: "collecting",
    requiredApprovals: 2,
    currentApprovals: 0,
    transactionDetails: {
      to: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
      value: "0.5 BTC",
      type: "Transfer"
    },
    initiator: "ops@example.com",
    createdAt: new Date(Date.now() - 7200000).toISOString(),
    expiresAt: new Date(Date.now() + 79200000).toISOString()
  },
  {
    id: "3",
    walletName: "Treasury Wallet",
    chain: "ethereum",
    status: "completed",
    requiredApprovals: 2,
    currentApprovals: 2,
    transactionDetails: {
      to: "0x1234...5678",
      value: "10 USDC",
      type: "ERC-20 Transfer"
    },
    initiator: "finance@example.com",
    createdAt: new Date(Date.now() - 86400000).toISOString(),
    broadcastTxHash: "0xabc123..."
  }
];

export const MpcSigningTab = ({ orgId, projectId }: MpcSigningTabProps) => {
  const [requests] = useState(mockSigningRequests);
  const [filter, setFilter] = useState<"all" | "pending" | "completed">("all");

  const filteredRequests = requests.filter((req) => {
    if (filter === "all") return true;
    if (filter === "pending") return ["pending", "collecting", "signing"].includes(req.status);
    return req.status === "completed" || req.status === "failed";
  });

  const getStatusBadge = (status: string) => {
    const statusConfig: Record<string, { color: string; icon: any; label: string }> = {
      pending: { color: "bg-yellow-500/20 text-yellow-500", icon: faClock, label: "Pending" },
      collecting: { color: "bg-blue-500/20 text-blue-500", icon: faKey, label: "Collecting" },
      signing: { color: "bg-purple-500/20 text-purple-500", icon: faKey, label: "Signing" },
      completed: { color: "bg-green-500/20 text-green-500", icon: faCheck, label: "Completed" },
      failed: { color: "bg-red-500/20 text-red-500", icon: faXmark, label: "Failed" },
      cancelled: { color: "bg-gray-500/20 text-gray-500", icon: faTimes, label: "Cancelled" }
    };

    const config = statusConfig[status] || statusConfig.pending;

    return (
      <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-medium ${config.color}`}>
        <FontAwesomeIcon icon={config.icon} className="h-3 w-3" />
        {config.label}
      </span>
    );
  };

  const formatTimeAgo = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  const getChainBadge = (chain: string) => {
    const chainColors: Record<string, string> = {
      ethereum: "bg-blue-500/20 text-blue-400",
      bitcoin: "bg-orange-500/20 text-orange-400",
      solana: "bg-purple-500/20 text-purple-400",
      lux: "bg-cyan-500/20 text-cyan-400",
      xrpl: "bg-gray-500/20 text-gray-400"
    };

    return (
      <span className={`rounded px-2 py-1 text-xs font-medium capitalize ${chainColors[chain] || chainColors.ethereum}`}>
        {chain}
      </span>
    );
  };

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium text-white">Signing Requests</h2>
          <p className="text-sm text-bunker-400">
            View and manage threshold signing requests across your wallets
          </p>
        </div>
        <div className="flex gap-2">
          <div className="flex rounded-lg bg-bunker-800 p-1">
            <button
              type="button"
              onClick={() => setFilter("all")}
              className={`rounded-md px-3 py-1 text-sm ${
                filter === "all" ? "bg-primary-500 text-white" : "text-bunker-300 hover:text-white"
              }`}
            >
              All
            </button>
            <button
              type="button"
              onClick={() => setFilter("pending")}
              className={`rounded-md px-3 py-1 text-sm ${
                filter === "pending" ? "bg-primary-500 text-white" : "text-bunker-300 hover:text-white"
              }`}
            >
              Pending
            </button>
            <button
              type="button"
              onClick={() => setFilter("completed")}
              className={`rounded-md px-3 py-1 text-sm ${
                filter === "completed" ? "bg-primary-500 text-white" : "text-bunker-300 hover:text-white"
              }`}
            >
              Completed
            </button>
          </div>
          <Button
            leftIcon={<FontAwesomeIcon icon={faPlus} />}
            colorSchema="primary"
          >
            New Request
          </Button>
        </div>
      </div>

      {filteredRequests.length === 0 ? (
        <EmptyState
          title="No signing requests"
          icon={faKey}
        >
          <p className="mb-4 text-sm text-bunker-300">
            {filter === "pending"
              ? "No pending signing requests at the moment."
              : filter === "completed"
                ? "No completed signing requests yet."
                : "Create a signing request to transfer funds from your MPC wallets."}
          </p>
        </EmptyState>
      ) : (
        <TableContainer>
          <Table>
            <THead>
              <Tr>
                <Th>Wallet</Th>
                <Th>Chain</Th>
                <Th>Transaction</Th>
                <Th>Status</Th>
                <Th>Approvals</Th>
                <Th>Initiator</Th>
                <Th>Created</Th>
                <Th className="w-16" />
              </Tr>
            </THead>
            <TBody>
              {filteredRequests.map((request) => (
                <Tr key={request.id}>
                  <Td>
                    <span className="font-medium text-white">{request.walletName}</span>
                  </Td>
                  <Td>{getChainBadge(request.chain)}</Td>
                  <Td>
                    <div>
                      <p className="text-sm text-white">{request.transactionDetails.type}</p>
                      <p className="text-xs text-bunker-400">
                        {request.transactionDetails.value} → {request.transactionDetails.to.slice(0, 10)}...
                      </p>
                    </div>
                  </Td>
                  <Td>{getStatusBadge(request.status)}</Td>
                  <Td>
                    <div className="flex items-center gap-2">
                      <div className="flex -space-x-1">
                        {Array.from({ length: request.requiredApprovals }).map((_, i) => (
                          <div
                            key={i}
                            className={`h-6 w-6 rounded-full border-2 border-bunker-800 ${
                              i < request.currentApprovals
                                ? "bg-green-500"
                                : "bg-bunker-700"
                            }`}
                          />
                        ))}
                      </div>
                      <span className="text-sm text-bunker-300">
                        {request.currentApprovals}/{request.requiredApprovals}
                      </span>
                    </div>
                  </Td>
                  <Td>
                    <span className="text-sm text-bunker-300">{request.initiator}</span>
                  </Td>
                  <Td>
                    <span className="text-sm text-bunker-300">{formatTimeAgo(request.createdAt)}</span>
                  </Td>
                  <Td>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="plain" colorSchema="secondary" size="xs">
                          <FontAwesomeIcon icon={faEllipsis} />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem icon={<FontAwesomeIcon icon={faEye} />}>
                          View Details
                        </DropdownMenuItem>
                        {["pending", "collecting"].includes(request.status) && (
                          <>
                            <DropdownMenuItem icon={<FontAwesomeIcon icon={faCheck} />}>
                              Approve
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              icon={<FontAwesomeIcon icon={faTimes} />}
                              className="text-red-500"
                            >
                              Reject
                            </DropdownMenuItem>
                          </>
                        )}
                        {request.broadcastTxHash && (
                          <DropdownMenuItem icon={<FontAwesomeIcon icon={faPaperPlane} />}>
                            View on Explorer
                          </DropdownMenuItem>
                        )}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        </TableContainer>
      )}
    </div>
  );
};
