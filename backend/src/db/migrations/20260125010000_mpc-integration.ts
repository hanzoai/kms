import { Knex } from "knex";

import { TableName } from "../schemas";
import { createOnUpdateTrigger, dropOnUpdateTrigger } from "../utils";

export async function up(knex: Knex): Promise<void> {
  // MPC Nodes table - tracks MPC cluster nodes
  if (!(await knex.schema.hasTable(TableName.MpcNodes))) {
    await knex.schema.createTable(TableName.MpcNodes, (t) => {
      t.uuid("id").primary().defaultTo(knex.fn.uuid());
      t.uuid("orgId").notNullable();
      t.foreign("orgId").references("id").inTable(TableName.Organization).onDelete("CASCADE");
      t.string("name").notNullable();
      t.string("nodeId").notNullable(); // P2P node identifier
      t.string("publicKey"); // Node's public key for verification
      t.string("endpoint"); // gRPC/HTTP endpoint
      t.integer("port").defaultTo(8080);
      t.enum("status", ["online", "offline", "syncing", "error"]).defaultTo("offline");
      t.jsonb("metadata").defaultTo("{}"); // Additional node metadata
      t.timestamp("lastSeen");
      t.timestamps(true, true, true);
      t.unique(["orgId", "nodeId"]);
    });
    await createOnUpdateTrigger(knex, TableName.MpcNodes);
  }

  // MPC Wallets table - multi-chain wallets managed by MPC
  if (!(await knex.schema.hasTable(TableName.MpcWallets))) {
    await knex.schema.createTable(TableName.MpcWallets, (t) => {
      t.uuid("id").primary().defaultTo(knex.fn.uuid());
      t.uuid("orgId").notNullable();
      t.foreign("orgId").references("id").inTable(TableName.Organization).onDelete("CASCADE");
      t.uuid("projectId");
      t.foreign("projectId").references("id").inTable(TableName.Project).onDelete("SET NULL");
      t.string("name").notNullable();
      t.string("walletId").notNullable(); // MPC wallet identifier
      t.enum("keyType", ["ecdsa", "eddsa", "taproot"]).notNullable().defaultTo("ecdsa");
      t.integer("threshold").notNullable().defaultTo(2);
      t.integer("totalParties").notNullable().defaultTo(3);
      t.jsonb("participantNodeIds").defaultTo("[]"); // Array of node IDs participating
      t.string("publicKey"); // Derived public key
      t.enum("status", ["pending", "active", "rotating", "archived"]).defaultTo("pending");
      t.jsonb("chainAddresses").defaultTo("{}"); // { "ethereum": "0x...", "bitcoin": "bc1..." }
      t.timestamps(true, true, true);
      t.unique(["orgId", "walletId"]);
    });
    await createOnUpdateTrigger(knex, TableName.MpcWallets);
  }

  // MPC Signing Requests table - tracks signing operations
  if (!(await knex.schema.hasTable(TableName.MpcSigningRequests))) {
    await knex.schema.createTable(TableName.MpcSigningRequests, (t) => {
      t.uuid("id").primary().defaultTo(knex.fn.uuid());
      t.uuid("walletId").notNullable();
      t.foreign("walletId").references("id").inTable(TableName.MpcWallets).onDelete("CASCADE");
      t.uuid("initiatorUserId");
      t.foreign("initiatorUserId").references("id").inTable(TableName.Users).onDelete("SET NULL");
      t.string("chain").notNullable(); // ethereum, bitcoin, solana, lux, xrpl
      t.string("txHash"); // Transaction hash to sign
      t.text("rawTransaction"); // Raw transaction data
      t.jsonb("transactionDetails").defaultTo("{}"); // Decoded transaction details
      t.enum("status", ["pending", "collecting", "signing", "completed", "failed", "cancelled"]).defaultTo("pending");
      t.jsonb("signatures").defaultTo("[]"); // Array of partial signatures
      t.text("finalSignature"); // Combined signature
      t.string("broadcastTxHash"); // On-chain transaction hash after broadcast
      t.text("errorMessage");
      t.integer("requiredApprovals").notNullable().defaultTo(2);
      t.timestamp("expiresAt");
      t.timestamps(true, true, true);
    });
    await createOnUpdateTrigger(knex, TableName.MpcSigningRequests);
  }

  // MPC Signing Approvals table - tracks individual approvals
  if (!(await knex.schema.hasTable(TableName.MpcSigningApprovals))) {
    await knex.schema.createTable(TableName.MpcSigningApprovals, (t) => {
      t.uuid("id").primary().defaultTo(knex.fn.uuid());
      t.uuid("signingRequestId").notNullable();
      t.foreign("signingRequestId").references("id").inTable(TableName.MpcSigningRequests).onDelete("CASCADE");
      t.uuid("userId");
      t.foreign("userId").references("id").inTable(TableName.Users).onDelete("SET NULL");
      t.uuid("nodeId");
      t.foreign("nodeId").references("id").inTable(TableName.MpcNodes).onDelete("SET NULL");
      t.enum("approvalType", ["user", "node"]).notNullable();
      t.enum("status", ["pending", "approved", "rejected"]).defaultTo("pending");
      t.text("signatureShare"); // Partial signature from this approver
      t.text("comment");
      t.timestamps(true, true, true);
      t.unique(["signingRequestId", "userId"]);
    });
    await createOnUpdateTrigger(knex, TableName.MpcSigningApprovals);
  }

  // MPC Wallet Tokens table - tracks tokens in wallets
  if (!(await knex.schema.hasTable(TableName.MpcWalletTokens))) {
    await knex.schema.createTable(TableName.MpcWalletTokens, (t) => {
      t.uuid("id").primary().defaultTo(knex.fn.uuid());
      t.uuid("walletId").notNullable();
      t.foreign("walletId").references("id").inTable(TableName.MpcWallets).onDelete("CASCADE");
      t.string("chain").notNullable();
      t.string("tokenAddress"); // null for native tokens
      t.string("symbol").notNullable();
      t.string("name");
      t.integer("decimals").defaultTo(18);
      t.string("balance").defaultTo("0");
      t.string("balanceUsd");
      t.timestamp("lastUpdated");
      t.timestamps(true, true, true);
      t.unique(["walletId", "chain", "tokenAddress"]);
    });
    await createOnUpdateTrigger(knex, TableName.MpcWalletTokens);
  }

  // MPC Transaction History table
  if (!(await knex.schema.hasTable(TableName.MpcTransactionHistory))) {
    await knex.schema.createTable(TableName.MpcTransactionHistory, (t) => {
      t.uuid("id").primary().defaultTo(knex.fn.uuid());
      t.uuid("walletId").notNullable();
      t.foreign("walletId").references("id").inTable(TableName.MpcWallets).onDelete("CASCADE");
      t.uuid("signingRequestId");
      t.foreign("signingRequestId").references("id").inTable(TableName.MpcSigningRequests).onDelete("SET NULL");
      t.string("chain").notNullable();
      t.string("txHash").notNullable();
      t.enum("type", ["send", "receive", "contract", "approve", "swap"]).notNullable();
      t.string("fromAddress");
      t.string("toAddress");
      t.string("amount");
      t.string("tokenAddress"); // null for native
      t.string("tokenSymbol");
      t.string("fee");
      t.enum("status", ["pending", "confirmed", "failed"]).defaultTo("pending");
      t.integer("confirmations").defaultTo(0);
      t.integer("blockNumber");
      t.timestamp("confirmedAt");
      t.timestamps(true, true, true);
      t.index(["walletId", "chain"]);
    });
    await createOnUpdateTrigger(knex, TableName.MpcTransactionHistory);
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists(TableName.MpcTransactionHistory);
  await dropOnUpdateTrigger(knex, TableName.MpcTransactionHistory);

  await knex.schema.dropTableIfExists(TableName.MpcWalletTokens);
  await dropOnUpdateTrigger(knex, TableName.MpcWalletTokens);

  await knex.schema.dropTableIfExists(TableName.MpcSigningApprovals);
  await dropOnUpdateTrigger(knex, TableName.MpcSigningApprovals);

  await knex.schema.dropTableIfExists(TableName.MpcSigningRequests);
  await dropOnUpdateTrigger(knex, TableName.MpcSigningRequests);

  await knex.schema.dropTableIfExists(TableName.MpcWallets);
  await dropOnUpdateTrigger(knex, TableName.MpcWallets);

  await knex.schema.dropTableIfExists(TableName.MpcNodes);
  await dropOnUpdateTrigger(knex, TableName.MpcNodes);
}
