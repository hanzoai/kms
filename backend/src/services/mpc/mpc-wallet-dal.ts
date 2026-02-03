import { Knex } from "knex";

import { TDbClient } from "@app/db";
import { TableName, TMpcWallets } from "@app/db/schemas";
import { DatabaseError } from "@app/lib/errors";
import { ormify, selectAllTableCols } from "@app/lib/knex";

export type TMpcWalletDALFactory = ReturnType<typeof mpcWalletDALFactory>;

export const mpcWalletDALFactory = (db: TDbClient) => {
  const mpcWalletOrm = ormify(db, TableName.MpcWallets);

  const findByOrgId = async (orgId: string, tx?: Knex) => {
    try {
      const docs = await (tx || db.replicaNode())(TableName.MpcWallets)
        .where({ orgId })
        .select(selectAllTableCols(TableName.MpcWallets))
        .orderBy("createdAt", "desc");
      return docs;
    } catch (error) {
      throw new DatabaseError({ error, name: "FindMpcWalletsByOrgId" });
    }
  };

  const findByProjectId = async (projectId: string, tx?: Knex) => {
    try {
      const docs = await (tx || db.replicaNode())(TableName.MpcWallets)
        .where({ projectId })
        .select(selectAllTableCols(TableName.MpcWallets))
        .orderBy("createdAt", "desc");
      return docs;
    } catch (error) {
      throw new DatabaseError({ error, name: "FindMpcWalletsByProjectId" });
    }
  };

  const findByWalletId = async (orgId: string, walletId: string, tx?: Knex) => {
    try {
      const doc = await (tx || db.replicaNode())(TableName.MpcWallets)
        .where({ orgId, walletId })
        .select(selectAllTableCols(TableName.MpcWallets))
        .first();
      return doc;
    } catch (error) {
      throw new DatabaseError({ error, name: "FindMpcWalletByWalletId" });
    }
  };

  const findActiveWallets = async (orgId: string, tx?: Knex) => {
    try {
      const docs = await (tx || db.replicaNode())(TableName.MpcWallets)
        .where({ orgId, status: "active" })
        .select(selectAllTableCols(TableName.MpcWallets))
        .orderBy("createdAt", "desc");
      return docs;
    } catch (error) {
      throw new DatabaseError({ error, name: "FindActiveMpcWallets" });
    }
  };

  const updateChainAddresses = async (id: string, chainAddresses: Record<string, string>, tx?: Knex) => {
    try {
      const [doc] = await (tx || db)(TableName.MpcWallets)
        .where({ id })
        .update({
          chainAddresses
        })
        .returning("*");
      return doc;
    } catch (error) {
      throw new DatabaseError({ error, name: "UpdateMpcWalletChainAddresses" });
    }
  };

  const updateStatus = async (id: string, status: TMpcWallets["status"], tx?: Knex) => {
    try {
      const [doc] = await (tx || db)(TableName.MpcWallets)
        .where({ id })
        .update({ status })
        .returning("*");
      return doc;
    } catch (error) {
      throw new DatabaseError({ error, name: "UpdateMpcWalletStatus" });
    }
  };

  return {
    ...mpcWalletOrm,
    findByOrgId,
    findByProjectId,
    findByWalletId,
    findActiveWallets,
    updateChainAddresses,
    updateStatus
  };
};
