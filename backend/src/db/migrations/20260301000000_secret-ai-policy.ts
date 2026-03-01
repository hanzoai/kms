import { Knex } from "knex";

import { TableName } from "../schemas";

export async function up(knex: Knex): Promise<void> {
  // Per-path AI access policies (auto-approve | requires-approval | blocked)
  await knex.schema.createTable(TableName.SecretAiPolicy, (t) => {
    t.uuid("id").primary().defaultTo(knex.fn.uuid());
    t.string("secretPath").notNullable();
    t.uuid("envId").notNullable().references("id").inTable(TableName.Environment).onDelete("CASCADE");
    t.string("policy").notNullable().defaultTo("auto-approve"); // auto-approve | requires-approval | blocked
    t.specificType("approverEmails", "text[]").nullable();
    t.integer("approvalTimeoutSeconds").notNullable().defaultTo(300);
    t.timestamps(true, true, true);
  });

  // Pending AI secret read requests (created when policy = requires-approval)
  await knex.schema.createTable(TableName.AiSecretReadRequest, (t) => {
    t.uuid("id").primary().defaultTo(knex.fn.uuid());
    t.uuid("policyId").notNullable().references("id").inTable(TableName.SecretAiPolicy).onDelete("CASCADE");
    t.uuid("identityId").notNullable().references("id").inTable(TableName.Identity).onDelete("CASCADE");
    t.string("secretKey").notNullable();
    t.string("secretPath").notNullable();
    t.string("environment").notNullable();
    t.string("projectId").notNullable();
    t.string("agentType").nullable();
    t.string("tool").nullable();
    t.string("deviceId").nullable();
    t.string("reason").nullable();
    t.string("status").notNullable().defaultTo("pending"); // pending | approved | denied | expired
    t.string("reviewedBy").nullable();
    t.timestamp("expiresAt").notNullable();
    t.timestamps(true, true, true);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists(TableName.AiSecretReadRequest);
  await knex.schema.dropTableIfExists(TableName.SecretAiPolicy);
}
