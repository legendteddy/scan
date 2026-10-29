import DataLoader from 'dataloader';
import { db } from './db.js';

const userLoader = new DataLoader(async (ids) => {
  const rows = await db.user.findMany({ where: { id: { in: ids } } });
  return ids.map((id) => rows.find((row) => row.id === id));
});

export const resolvers = {
  Query: {
    user: (_parent, { id }) => userLoader.load(id),
    search: (_parent, { q }, ctx) =>
      db.$queryRaw`SELECT * FROM docs WHERE tenant_id = ${ctx.tenantId} AND title ILIKE ${'%' + q + '%'}`,
  },
  Mutation: {
    deleteInvoice: (_parent, { id }) => db.invoice.delete({ where: { id } }),
    updateEmail: (_parent, { userId, email }) =>
      db.user.update({ where: { id: userId }, data: { email } }),
  },
};
