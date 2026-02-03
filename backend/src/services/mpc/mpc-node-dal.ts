import { Knex } from "knex";

import { TDbClient } from "@app/db";
import { TableName, TMpcNodes, TMpcNodesInsert, TMpcNodesUpdate } from "@app/db/schemas";
import { DatabaseError } from "@app/lib/errors";
import { ormify, selectAllTableCols } from "@app/lib/knex";

export type TMpcNodeDALFactory = ReturnType<typeof mpcNodeDALFactory>;

export const mpcNodeDALFactory = (db: TDbClient) => {
  const mpcNodeOrm = ormify(db, TableName.MpcNodes);

  const findByOrgId = async (orgId: string, tx?: Knex) => {
    try {
      const doc = await (tx || db.replicaNode())(TableName.MpcNodes)
        .where({ orgId })
        .select(selectAllTableCols(TableName.MpcNodes))
        .orderBy("createdAt", "desc");
      return doc;
    } catch (error) {
      throw new DatabaseError({ error, name: "FindMpcNodesByOrgId" });
    }
  };

  const findByNodeId = async (orgId: string, nodeId: string, tx?: Knex) => {
    try {
      const doc = await (tx || db.replicaNode())(TableName.MpcNodes)
        .where({ orgId, nodeId })
        .select(selectAllTableCols(TableName.MpcNodes))
        .first();
      return doc;
    } catch (error) {
      throw new DatabaseError({ error, name: "FindMpcNodeByNodeId" });
    }
  };

  const updateStatus = async (id: string, status: TMpcNodes["status"], lastSeen?: Date, tx?: Knex) => {
    try {
      const [doc] = await (tx || db)(TableName.MpcNodes)
        .where({ id })
        .update({
          status,
          lastSeen: lastSeen || new Date()
        })
        .returning("*");
      return doc;
    } catch (error) {
      throw new DatabaseError({ error, name: "UpdateMpcNodeStatus" });
    }
  };

  const findOnlineNodes = async (orgId: string, tx?: Knex) => {
    try {
      const docs = await (tx || db.replicaNode())(TableName.MpcNodes)
        .where({ orgId, status: "online" })
        .select(selectAllTableCols(TableName.MpcNodes));
      return docs;
    } catch (error) {
      throw new DatabaseError({ error, name: "FindOnlineMpcNodes" });
    }
  };

  return {
    ...mpcNodeOrm,
    findByOrgId,
    findByNodeId,
    updateStatus,
    findOnlineNodes
  };
};
