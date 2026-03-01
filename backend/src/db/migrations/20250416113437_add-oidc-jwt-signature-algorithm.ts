import { Knex } from "knex";


import { TableName } from "../schemas";

export async function up(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasColumn(TableName.OidcConfig, "jwtSignatureAlgorithm"))) {
    await knex.schema.alterTable(TableName.OidcConfig, (t) => {
      t.string("jwtSignatureAlgorithm").defaultTo(OIDCJWTSignatureAlgorithm.RS256).notNullable();
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  if (await knex.schema.hasColumn(TableName.OidcConfig, "jwtSignatureAlgorithm")) {
    await knex.schema.alterTable(TableName.OidcConfig, (t) => {
      t.dropColumn("jwtSignatureAlgorithm");
    });
  }
}
