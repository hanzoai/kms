import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  Button,
  FormControl,
  Input,
  Modal,
  ModalContent
} from "@app/components/v2";

interface AddNodeModalProps {
  isOpen: boolean;
  onClose: () => void;
  orgId: string;
}

const formSchema = z.object({
  name: z.string().min(1, "Name is required").max(100),
  endpoint: z.string().url("Must be a valid URL"),
  port: z.number().min(1).max(65535),
  authToken: z.string().optional()
});

type FormData = z.infer<typeof formSchema>;

export const AddNodeModal = ({
  isOpen,
  onClose,
  orgId
}: AddNodeModalProps) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<"idle" | "testing" | "success" | "error">("idle");

  const {
    register,
    handleSubmit,
    reset,
    watch,
    formState: { errors }
  } = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: "",
      endpoint: "https://",
      port: 8080,
      authToken: ""
    }
  });

  const endpoint = watch("endpoint");
  const port = watch("port");

  const testConnection = async () => {
    if (!endpoint || !port) return;

    setConnectionStatus("testing");
    try {
      // TODO: Call API to test node connection
      console.log("Testing connection to:", `${endpoint}:${port}`);

      // Simulate API call
      await new Promise((resolve) => setTimeout(resolve, 1500));

      setConnectionStatus("success");
    } catch (error) {
      console.error("Connection test failed:", error);
      setConnectionStatus("error");
    }
  };

  const onSubmit = async (data: FormData) => {
    setIsSubmitting(true);
    try {
      // TODO: Call API to add node
      console.log("Adding node:", { ...data, orgId });

      // Simulate API call
      await new Promise((resolve) => setTimeout(resolve, 1000));

      reset();
      setConnectionStatus("idle");
      onClose();
    } catch (error) {
      console.error("Failed to add node:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    reset();
    setConnectionStatus("idle");
    onClose();
  };

  const getConnectionStatusText = () => {
    switch (connectionStatus) {
      case "testing":
        return <span className="text-yellow-500">Testing connection...</span>;
      case "success":
        return <span className="text-green-500">Connection successful</span>;
      case "error":
        return <span className="text-red-500">Connection failed</span>;
      default:
        return null;
    }
  };

  return (
    <Modal isOpen={isOpen} onOpenChange={(open) => !open && handleClose()}>
      <ModalContent
        title="Add MPC Node"
        subTitle="Register a new MPC node to participate in threshold signing"
      >
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <FormControl
            label="Node Name"
            isRequired
            errorText={errors.name?.message}
            isError={!!errors.name}
          >
            <Input
              {...register("name")}
              placeholder="e.g., Primary Node"
              autoComplete="off"
            />
          </FormControl>

          <FormControl
            label="Endpoint URL"
            isRequired
            errorText={errors.endpoint?.message}
            isError={!!errors.endpoint}
          >
            <Input
              {...register("endpoint")}
              placeholder="https://mpc-node.example.com"
              autoComplete="off"
            />
          </FormControl>

          <FormControl
            label="Port"
            isRequired
            errorText={errors.port?.message}
            isError={!!errors.port}
          >
            <Input
              type="number"
              min={1}
              max={65535}
              {...register("port", { valueAsNumber: true })}
            />
          </FormControl>

          <FormControl
            label="Authentication Token"
            helperText="Optional: Token for authenticating with the MPC node"
            errorText={errors.authToken?.message}
            isError={!!errors.authToken}
          >
            <Input
              {...register("authToken")}
              type="password"
              placeholder="Enter auth token (optional)"
              autoComplete="off"
            />
          </FormControl>

          <div className="rounded-lg border border-bunker-600 bg-bunker-800 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-white">Test Connection</p>
                <p className="text-xs text-bunker-400">
                  Verify the node is reachable before adding
                </p>
              </div>
              <Button
                type="button"
                variant="outline_bg"
                colorSchema="secondary"
                size="sm"
                onClick={testConnection}
                isLoading={connectionStatus === "testing"}
                isDisabled={!endpoint || connectionStatus === "testing"}
              >
                Test
              </Button>
            </div>
            {connectionStatus !== "idle" && (
              <div className="mt-2 text-sm">{getConnectionStatusText()}</div>
            )}
          </div>

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
              Add Node
            </Button>
          </div>
        </form>
      </ModalContent>
    </Modal>
  );
};
