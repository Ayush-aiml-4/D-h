import { db } from '../db/index.ts';
import { users } from '../db/schema.ts';
import { eq } from 'drizzle-orm';

export interface AuthUserInfo {
  uid: string;
  email?: string;
  name?: string;
  role?: string;
}

/** In-memory user map used when PostgreSQL is unavailable (local demo mode). */
const memoryUsers = new Map<string, {
  id: number;
  uid: string;
  name: string;
  email: string;
  role: string;
  createdAt: Date | null;
}>();

let memoryUserSeq = 1;

function toMemoryUser(userPayload: AuthUserInfo) {
  const existing = memoryUsers.get(userPayload.uid);
  if (existing) return existing;

  const name = userPayload.name || (userPayload.email ? userPayload.email.split('@')[0] : 'Researcher');
  const email = userPayload.email || `${userPayload.uid}@devilhunt.local`;
  const role = userPayload.role || 'RESEARCHER';
  const record = {
    id: memoryUserSeq++,
    uid: userPayload.uid,
    name,
    email,
    role,
    createdAt: new Date(),
  };
  memoryUsers.set(userPayload.uid, record);
  return record;
}

export const syncUserRecord = async (userPayload: AuthUserInfo, tx?: any) => {
  const dbClient = tx || db;
  try {
    const existing = await dbClient.select().from(users).where(eq(users.uid, userPayload.uid));
    if (existing.length > 0) {
      return existing[0];
    }

    const name = userPayload.name || (userPayload.email ? userPayload.email.split('@')[0] : 'Researcher');
    const email = userPayload.email || `${userPayload.uid}@devilhunt.local`;
    const role = userPayload.role || 'RESEARCHER';

    const [created] = await dbClient
      .insert(users)
      .values({
        uid: userPayload.uid,
        name,
        email,
        role,
      })
      .returning();

    return created;
  } catch (err) {
    // Local / demo mode: no PostgreSQL — use in-memory profile so the UI stays fully usable
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[userService] DB unavailable — using in-memory user for local demo:', userPayload.uid);
      return toMemoryUser(userPayload) as any;
    }
    console.error('Error syncing user record in DB:', err);
    throw new Error('Failed to synchronize user profile record', { cause: err });
  }
};

export const getUserByUid = async (uid: string) => {
  try {
    const existing = await db.select().from(users).where(eq(users.uid, uid));
    return existing.length > 0 ? existing[0] : null;
  } catch {
    return memoryUsers.get(uid) || null;
  }
};
