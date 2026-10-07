import { db } from '../db/index.ts';
import { rewards, reports } from '../db/schema.ts';
import { eq, inArray } from 'drizzle-orm';
import { AuthUser } from '../middleware/auth.ts';

export const getRewards = async (user: AuthUser) => {
  try {
    if (user.role === 'ADMIN') {
      return await db.select().from(rewards);
    }
    const userReports = await db.select().from(reports).where(eq(reports.researcherId, user.uid));
    if (userReports.length === 0) return [];
    const reportIds = userReports.map((r) => r.id);
    return await db.select().from(rewards).where(inArray(rewards.reportId, reportIds));
  } catch (err) {
    console.error('Failed to query rewards:', err);
    throw new Error('Database error fetching rewards', { cause: err });
  }
};

export const getRewardMetrics = async (user: AuthUser) => {
  try {
    const allRewards = await getRewards(user);

    const paidSum = allRewards
      .filter((r) => r.status === 'PAID')
      .reduce((sum, r) => sum + r.numericAmount, 0);

    const pendingSum = allRewards
      .filter((r) => r.status === 'PENDING')
      .reduce((sum, r) => sum + r.numericAmount, 0);

    const potentialSum = allRewards
      .reduce((sum, r) => sum + r.numericAmount, 0);

    return {
      paid: paidSum,
      pending: pendingSum,
      potential: potentialSum,
      formattedPaid: `₹${paidSum.toLocaleString('en-IN')}`,
      formattedPending: `₹${pendingSum.toLocaleString('en-IN')}`,
      formattedPotential: `₹${potentialSum.toLocaleString('en-IN')}`,
    };
  } catch (err) {
    console.error('Failed to compute reward metrics:', err);
    throw new Error('Database error computing reward metrics', { cause: err });
  }
};

