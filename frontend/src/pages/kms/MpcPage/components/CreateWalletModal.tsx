import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  Button,
  FormControl,
  Input,
  Modal,
  ModalContent,
  Select,
  SelectItem
} from "@app/components/v2";

interface CreateWalletModalProps {
  isOpen: boolean;
  onClose: () => void;
  orgId: string;
  projectId: string;
}

const formSchema = z.object({
  name: z.string().min(1, "Name is required").max(100),
  keyType: z.enum(["ecdsa", "eddsa"]),
  threshold: z.number().min(1).max(10),
  totalParties: z.number().min(2).max(20),
  chains: z.array(z.string()).min(1, "Select at least one chain")
});

type FormData = z.infer<typeof formSchema>;

const SUPPORTED_CHAINS = [
  { value: "ethereum", label: "Ethereum" },
  { value: "bitcoin", label: "Bitcoin" },
  { value: "solana", label: "Solana" },
  { value: "lux", label: "Lux Network" },
  { value: "xrpl", label: "XRP Ledger" }
];

const KEY_TYPES = [
  { value: "ecdsa", label: "ECDSA (secp256k1)", description: "Bitcoin, Ethereum, Lux C-Chain" },
  { value: "eddsa", label: "EdDSA (Ed25519)", description: "Solana, Lux X/P-Chain" }
];

export const CreateWalletModal = ({
  isOpen,
  onClose,
  orgId,
  projectId
}: CreateWalletModalProps) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [selectedChains, setSelectedChains] = useState<string[]>([]);

  const {
    register,
    handleSubmit,
    reset,
    watch,
    setValue,
    formState: { errors }
  } = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: "",
      keyType: "ecdsa",
      threshold: 2,
      totalParties: 3,
      chains: []
    }
  });

  const threshold = watch("threshold");
  const totalParties = watch("totalParties");

  const onSubmit = async (data: FormData) => {
    setIsSubmitting(true);
    try {
      // TODO: Call API to create wallet
      console.log("Creating wallet:", { ...data, orgId, projectId });

      // Simulate API call
      await new Promise((resolve) => setTimeout(resolve, 1000));

      reset();
      setSelectedChains([]);
      onClose();
    } catch (error) {
      console.error("Failed to create wallet:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    reset();
    setSelectedChains([]);
    onClose();
  };

  const toggleChain = (chain: string) => {
    const newChains = selectedChains.includes(chain)
      ? selectedChains.filter((c) => c !== chain)
      : [...selectedChains, chain];
    setSelectedChains(newChains);
    setValue("chains", newChains);
  };

  return (
    <Modal isOpen={isOpen} onOpenChange={(open) => !open && handleClose()}>
      <ModalContent
        title="Create MPC Wallet"
        subTitle="Create a new multi-party computation wallet with threshold signing"
      >
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <FormControl
            label="Wallet Name"
            isRequired
            errorText={errors.name?.message}
            isError={!!errors.name}
          >
            <Input
              {...register("name")}
              placeholder="e.g., Treasury Wallet"
              autoComplete="off"
            />
          </FormControl>

          <FormControl
            label="Key Type"
            isRequired
            errorText={errors.keyType?.message}
            isError={!!errors.keyType}
          >
            <Select
              value={watch("keyType")}
              onValueChange={(value) => setValue("keyType", value as "ecdsa" | "eddsa")}
              className="w-full"
            >
              {KEY_TYPES.map((type) => (
                <SelectItem key={type.value} value={type.value}>
                  <div>
                    <span className="font-medium">{type.label}</span>
                    <span className="ml-2 text-xs text-bunker-400">{type.description}</span>
                  </div>
                </SelectItem>
              ))}
            </Select>
          </FormControl>

          <div className="grid grid-cols-2 gap-4">
            <FormControl
              label="Threshold (t)"
              isRequired
              errorText={errors.threshold?.message}
              isError={!!errors.threshold}
            >
              <Input
                type="number"
                min={1}
                max={totalParties - 1}
                {...register("threshold", { valueAsNumber: true })}
              />
            </FormControl>

            <FormControl
              label="Total Parties (n)"
              isRequired
              errorText={errors.totalParties?.message}
              isError={!!errors.totalParties}
            >
              <Input
                type="number"
                min={threshold + 1}
                max={20}
                {...register("totalParties", { valueAsNumber: true })}
              />
            </FormControl>
          </div>

          <p className="text-xs text-bunker-400">
            {threshold} of {totalParties} parties will be required to sign transactions
          </p>

          <FormControl
            label="Supported Chains"
            isRequired
            errorText={errors.chains?.message}
            isError={!!errors.chains}
          >
            <div className="flex flex-wrap gap-2">
              {SUPPORTED_CHAINS.map((chain) => (
                <button
                  key={chain.value}
                  type="button"
                  onClick={() => toggleChain(chain.value)}
                  className={`rounded-lg border px-3 py-2 text-sm transition-colors ${
                    selectedChains.includes(chain.value)
                      ? "border-primary-500 bg-primary-500/10 text-primary-500"
                      : "border-bunker-600 bg-bunker-800 text-bunker-300 hover:border-bunker-500"
                  }`}
                >
                  {chain.label}
                </button>
              ))}
            </div>
          </FormControl>

          <div className="mt-6 flex justify-end gap-2">
            <Button
              type="button"
              variant="plain"
              colorSchema="secondary"
              onClick={handleClose}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              colorSchema="primary"
              isLoading={isSubmitting}
              isDisabled={isSubmitting}
            >
              Create Wallet
            </Button>
          </div>
        </form>
      </ModalContent>
    </Modal>
  );
};
