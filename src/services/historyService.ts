import { db } from '../db/index.ts';
import { historySessions, programs, assets } from '../db/schema.ts';
import { desc, eq } from 'drizzle-orm';
import { AuthUser } from '../middleware/auth.ts';

export const getHistorySessions = async (user: AuthUser) => {
  try {
    const allHistory = user.role === 'ADMIN'
      ? await db.select().from(historySessions).orderBy(desc(historySessions.createdAt))
      : await db.select().from(historySessions).where(eq(historySessions.researcherId, user.uid)).orderBy(desc(historySessions.createdAt));

    const allPrograms = await db.select().from(programs);
    const allAssets = await db.select().from(assets);

    return allHistory.map((h) => {
      const prog = allPrograms.find((p) => p.id === h.programId);
      const asset = allAssets.find((a) => a.id === h.targetId);

      return {
        ...h,
        programName: prog ? prog.name : 'Security Program',
        target: asset ? asset.domain : 'Target Domain',
        date: 'Today',
        potentialFindings: 0,
        verifiedFindings: h.verifiedFindingCount,
        reportStatus: 'Draft',
        bountyEarned: h.rewardAmount,
      };
    });
  } catch (err) {
    console.error('Failed to query history sessions:', err);
    throw new Error('Database error fetching history sessions', { cause: err });
  }
};

