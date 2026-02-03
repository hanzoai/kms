import { useState } from "react";
import {
  faEthereum,
  faBitcoin
} from "@fortawesome/free-brands-svg-icons";
import {
  faCircleCheck,
  faCopy,
  faEllipsis,
  faKey,
  faPlus,
  faTrash,
  faWallet
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  EmptyState,
  Modal,
  ModalContent,
  Table,
  TableContainer,
  TBody,
  Td,
  Th,
  THead,
  Tr
} from "@app/components/v2";

import { CreateWalletModal } from "./CreateWalletModal";

interface MpcWalletsTabProps {
  orgId: string;
  projectId: string;
}

// Mock data for demonstration
const mockWallets = [
  {
    id: "1",
    name: "Treasury Wallet",
    walletId: "wallet_abc123",
    keyType: "ecdsa",
    threshold: 2,
    totalParties: 3,
    status: "active",
    publicKey: "0x04abc...",
    chainAddresses: {
      ethereum: "0x742d35Cc6634C0532925a3b844Bc9e7595f1D123",
      bitcoin: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    },
    createdAt: new Date().toISOString()
  }
];

const chainIcons: Record<string, any> = {
  ethereum: faEthereum,
  bitcoin: faBitcoin,
  solana: faWallet,
  lux: faWallet,
  xrpl: faWallet
};

export const MpcWalletsTab = ({ orgId, projectId }: MpcWalletsTabProps) => {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [wallets] = useState(mockWallets);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    // TODO: Show toast notification
  };

  const getStatusBadge = (status: string) => {
    const statusColors: Record<string, string> = {
      active: "bg-green-500/20 text-green-500",
      pending: "bg-yellow-500/20 text-yellow-500",
      rotating: "bg-blue-500/20 text-blue-500",
      archived: "bg-gray-500/20 text-gray-500"
    };

    return (
      <span className={`rounded-full px-2 py-1 text-xs font-medium ${statusColors[status] || statusColors.pending}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    );
  };

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-medium text-white">MPC Wallets</h2>
        <Button
          leftIcon={<FontAwesomeIcon icon={faPlus} />}
          colorSchema="primary"
          onClick={() => setIsCreateModalOpen(true)}
        >
          Create Wallet
        </Button>
      </div>

      {wallets.length === 0 ? (
        <EmptyState
          title="No MPC wallets yet"
          icon={faWallet}
        >
          <p className="mb-4 text-sm text-bunker-300">
            Create your first MPC wallet to start managing multi-chain assets with threshold security.
          </p>
          <Button
            leftIcon={<FontAwesomeIcon icon={faPlus} />}
            colorSchema="primary"
            onClick={() => setIsCreateModalOpen(true)}
          >
            Create Wallet
          </Button>
        </EmptyState>
      ) : (
        <TableContainer>
          <Table>
            <THead>
              <Tr>
                <Th>Name</Th>
                <Th>Key Type</Th>
                <Th>Threshold</Th>
                <Th>Status</Th>
                <Th>Addresses</Th>
                <Th className="w-16" />
              </Tr>
            </THead>
            <TBody>
              {wallets.map((wallet) => (
                <Tr key={wallet.id}>
                  <Td>
                    <div className="flex items-center gap-3">
                      <div className="rounded-lg bg-primary-500/10 p-2">
                        <FontAwesomeIcon icon={faWallet} className="text-primary-500" />
                      </div>
                      <div>
                        <p className="font-medium text-white">{wallet.name}</p>
                        <p className="text-xs text-bunker-400">{wallet.walletId}</p>
                      </div>
                    </div>
                  </Td>
                  <Td>
                    <span className="rounded bg-bunker-700 px-2 py-1 text-xs font-medium uppercase text-bunker-200">
                      {wallet.keyType}
                    </span>
                  </Td>
                  <Td>
                    <span className="text-white">
                      {wallet.threshold} of {wallet.totalParties}
                    </span>
                  </Td>
                  <Td>{getStatusBadge(wallet.status)}</Td>
                  <Td>
                    <div className="flex flex-col gap-1">
                      {Object.entries(wallet.chainAddresses).map(([chain, address]) => (
                        <div key={chain} className="flex items-center gap-2">
                          <FontAwesomeIcon
                            icon={chainIcons[chain] || faWallet}
                            className="h-3 w-3 text-bunker-400"
                          />
                          <span className="text-xs text-bunker-300">{chain}:</span>
                          <span className="max-w-[120px] truncate text-xs text-white">
                            {address}
                          </span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(address)}
                            className="text-bunker-400 hover:text-white"
                          >
                            <FontAwesomeIcon icon={faCopy} className="h-3 w-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </Td>
                  <Td>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="plain" colorSchema="secondary" size="xs">
                          <FontAwesomeIcon icon={faEllipsis} />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem icon={<FontAwesomeIcon icon={faKey} />}>
                          Sign Transaction
                        </DropdownMenuItem>
                        <DropdownMenuItem icon={<FontAwesomeIcon icon={faCircleCheck} />}>
                          View Details
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          icon={<FontAwesomeIcon icon={faTrash} />}
                          className="text-red-500"
                        >
                          Archive Wallet
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

      <CreateWalletModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        orgId={orgId}
        projectId={projectId}
      />
    </div>
  );
};
