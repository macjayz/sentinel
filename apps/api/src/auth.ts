import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

export const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const derived = (await scrypt(password, salt, 64)) as Buffer;
  return `${salt}:${derived.toString("hex")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;

  const expected = Buffer.from(hash, "hex");
  const derived = (await scrypt(password, salt, expected.length)) as Buffer;
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function generateSessionToken(): string {
  return `sentinel_session_${randomBytes(32).toString("base64url")}`;
}

const ROLE_RANK: Record<string, number> = { viewer: 0, developer: 1, admin: 2, owner: 3 };

export function roleMeetsMinimum(role: string | null | undefined, minimum: string): boolean {
  if (!role) return false;
  const roleRank = ROLE_RANK[role];
  const minimumRank = ROLE_RANK[minimum];
  if (roleRank === undefined || minimumRank === undefined) return false;
  return roleRank >= minimumRank;
}
