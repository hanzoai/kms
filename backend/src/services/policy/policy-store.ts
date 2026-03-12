import { Capability, type Policy, type PolicyInput } from "./policy-types";

const MAX_CACHE_SIZE = 1024;

// Built-in default policy: basic self-service operations
const DEFAULT_POLICY: Policy = {
  name: "default",
  rules: [
    { path: "auth/token/lookup-self", capabilities: [Capability.Read] },
    { path: "auth/token/renew-self", capabilities: [Capability.Update] },
    { path: "auth/token/revoke-self", capabilities: [Capability.Update] },
    { path: "sys/capabilities-self", capabilities: [Capability.Update] },
    { path: "sys/internal/*", capabilities: [Capability.Read] }
  ],
  createdAt: new Date("2024-01-01"),
  updatedAt: new Date("2024-01-01")
};

export class PolicyStore {
  private policies = new Map<string, Policy>();
  private cache = new Map<string, Policy>();
  private cacheOrder: string[] = [];

  constructor() {
    this.policies.set("default", DEFAULT_POLICY);
  }

  create(input: PolicyInput): Policy {
    if (input.name === "default") throw new Error("policy: cannot overwrite default policy");
    if (this.policies.has(input.name)) throw new Error(`policy: "${input.name}" already exists`);

    const policy = this.parseInput(input);
    this.policies.set(input.name, policy);
    this.invalidateCache(input.name);
    return policy;
  }

  get(name: string): Policy | undefined {
    const cached = this.cache.get(name);
    if (cached) return cached;

    const policy = this.policies.get(name);
    if (policy) this.addToCache(name, policy);
    return policy;
  }

  getMultiple(names: string[]): Policy[] {
    const result: Policy[] = [];
    for (const name of names) {
      const policy = this.get(name);
      if (policy) result.push(policy);
    }
    return result;
  }

  update(input: PolicyInput): Policy {
    if (input.name === "default") throw new Error("policy: cannot modify default policy");
    if (!this.policies.has(input.name)) throw new Error(`policy: "${input.name}" not found`);

    const policy = this.parseInput(input);
    this.policies.set(input.name, policy);
    this.invalidateCache(input.name);
    return policy;
  }

  delete(name: string): void {
    if (name === "default") throw new Error("policy: cannot delete default policy");
    this.policies.delete(name);
    this.invalidateCache(name);
  }

  list(): string[] {
    return Array.from(this.policies.keys()).sort();
  }

  private parseInput(input: PolicyInput): Policy {
    const now = new Date();
    const rules = Object.entries(input.path).map(([path, config]) => ({
      path,
      capabilities: config.capabilities.map((c) => c as Capability),
      ...(config.allowed_parameters ? { allowedParameters: config.allowed_parameters } : {}),
      ...(config.denied_parameters ? { deniedParameters: config.denied_parameters } : {}),
      ...(config.required_parameters ? { requiredParameters: config.required_parameters } : {})
    }));

    return {
      name: input.name,
      rules,
      createdAt: this.policies.get(input.name)?.createdAt ?? now,
      updatedAt: now
    };
  }

  private addToCache(name: string, policy: Policy): void {
    if (this.cache.size >= MAX_CACHE_SIZE) {
      const evict = this.cacheOrder.shift();
      if (evict) this.cache.delete(evict);
    }
    this.cache.set(name, policy);
    this.cacheOrder.push(name);
  }

  private invalidateCache(name: string): void {
    this.cache.delete(name);
    this.cacheOrder = this.cacheOrder.filter((n) => n !== name);
  }
}
