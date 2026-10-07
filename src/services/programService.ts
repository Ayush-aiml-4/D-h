import { db } from '../db/index.ts';
import { programs, assets, policyRules } from '../db/schema.ts';
import { eq } from 'drizzle-orm';
import { Program } from '../types.ts';

export const getPrograms = async (): Promise<Program[]> => {
  try {
    const allPrograms = await db.select().from(programs);
    const allAssets = await db.select().from(assets);
    const allRules = await db.select().from(policyRules);

    return allPrograms.map((prog) => {
      const progAssets = allAssets.filter((a) => a.programId === prog.id);
      const progRules = allRules.filter((r) => r.programId === prog.id);

      return {
        id: prog.id,
        name: prog.name,
        organization: `${prog.name.split(' ')[0]} Corp`,
        targetCount: progAssets.length || 1,
        scopeStatus: 'Authorized',
        rulesLoaded: prog.rulesLoaded,
        rewardMax: prog.rewardCeiling,
        lastHunt: '15 mins ago',
        status: (prog.status === 'ACTIVE' ? 'Active' : prog.status) as any,
        targets: progAssets.map((a) => a.domain),
        rulesAllowed: progRules.filter((r) => r.allowed).map((r) => r.name),
        rulesBlocked: progRules.filter((r) => !r.allowed).map((r) => r.name),
        description: prog.description,
      };
    });
  } catch (err) {
    console.error('Failed to query programs:', err);
    throw new Error('Failed to fetch programs from database', { cause: err });
  }
};

export const getProgramById = async (id: string): Promise<Program | null> => {
  try {
    const prog = await db.select().from(programs).where(eq(programs.id, id));
    if (prog.length === 0) return null;

    const progAssets = await db.select().from(assets).where(eq(assets.programId, id));
    const progRules = await db.select().from(policyRules).where(eq(policyRules.programId, id));
    const p = prog[0];

    return {
      id: p.id,
      name: p.name,
      organization: `${p.name.split(' ')[0]} Corp`,
      targetCount: progAssets.length || 1,
      scopeStatus: 'Authorized',
      rulesLoaded: p.rulesLoaded,
      rewardMax: p.rewardCeiling,
      lastHunt: '15 mins ago',
      status: (p.status === 'ACTIVE' ? 'Active' : p.status) as any,
      targets: progAssets.map((a) => a.domain),
      rulesAllowed: progRules.filter((r) => r.allowed).map((r) => r.name),
      rulesBlocked: progRules.filter((r) => !r.allowed).map((r) => r.name),
      description: p.description,
    };
  } catch (err) {
    console.error('Failed to query program by ID:', err);
    throw new Error('Failed to fetch program by ID', { cause: err });
  }
};

export const getProgramAssets = async (programId: string) => {
  try {
    return await db.select().from(assets).where(eq(assets.programId, programId));
  } catch (err) {
    console.error('Failed to query program assets:', err);
    throw new Error('Failed to fetch program assets', { cause: err });
  }
};
