// Stub: EE group DAL type export (MIT re-implementation)
// The actual group data lives in services/membership-group/
import { TDbClient } from "@app/db";

export type TGroupDALFactory = ReturnType<typeof groupDALFactory>;

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const groupDALFactory = (_db: TDbClient) => ({
  findOne: async (..._args: unknown[]) => null as any,
  findById: async (..._args: unknown[]) => null as any,
  find: async (..._args: unknown[]) => [] as any[],
  findAllGroupPossibleUsers: async (..._args: unknown[]) => [] as any[],
});
