// Real trusted-IP service backed by the database.
// CIDR matching uses ipaddr.js (already available as a transitive dependency).

import ipaddr from "ipaddr.js";

import { TTrustedIps, TTrustedIpsInsert, TTrustedIpsUpdate } from "@app/db/schemas";
import { logger } from "@app/lib/logger";

import { TTrustedIpDALFactory } from "./trusted-ip-dal";

type TTrustedIpServiceFactoryDep = {
  trustedIpDAL: TTrustedIpDALFactory;
};

export type TTrustedIpServiceFactory = ReturnType<typeof trustedIpServiceFactory>;

export const trustedIpServiceFactory = ({ trustedIpDAL }: TTrustedIpServiceFactoryDep) => {
  const getTrustedIps = async (projectId: string): Promise<TTrustedIps[]> => {
    return trustedIpDAL.find({ projectId });
  };

  const addTrustedIp = async (data: TTrustedIpsInsert): Promise<TTrustedIps> => {
    return trustedIpDAL.create(data);
  };

  const updateTrustedIp = async (
    data: { id: string } & TTrustedIpsUpdate
  ): Promise<TTrustedIps> => {
    const { id, ...update } = data;
    const [updated] = await trustedIpDAL.update({ id }, update);
    return updated;
  };

  const deleteTrustedIp = async (data: { id: string; projectId: string }): Promise<TTrustedIps> => {
    const [deleted] = await trustedIpDAL.delete({ id: data.id, projectId: data.projectId });
    return deleted;
  };

  // Returns true when:
  //   - No active trusted IPs configured for the project (open access), or
  //   - The provided IP matches at least one active trusted IP or CIDR range.
  const isIpAllowed = async (projectId: string, ip: string): Promise<boolean> => {
    try {
      const records = await trustedIpDAL.find({ projectId, isActive: true });
      if (records.length === 0) return true;

      let parsed: ipaddr.IPv4 | ipaddr.IPv6;
      try {
        parsed = ipaddr.parse(ip);
      } catch {
        logger.warn({ ip }, "trusted-ip: failed to parse request IP — denying");
        return false;
      }

      for (const record of records) {
        try {
          if (record.prefix != null) {
            // CIDR range
            const net = ipaddr.parseCIDR(`${record.ipAddress}/${record.prefix}`);
            if (parsed.match(net)) return true;
          } else {
            // Exact IP
            if (parsed.toString() === ipaddr.parse(record.ipAddress).toString()) return true;
          }
        } catch (err) {
          logger.warn({ record, err }, "trusted-ip: skipping malformed record");
        }
      }

      return false;
    } catch (err) {
      // On DB error fail open to avoid blocking legitimate traffic.
      logger.error(err, "trusted-ip: isIpAllowed DB error — defaulting to allow");
      return true;
    }
  };

  return { getTrustedIps, addTrustedIp, updateTrustedIp, deleteTrustedIp, isIpAllowed };
};
