import "server-only";
import crypto from "node:crypto";

export const SESSION_COOKIE = "recon_session";
const DEFAULT_TTL_HOURS = 12;

function secret(): string {
  return process.env.AUTH_SECRET || process.env.AUTH_PASSWORD || "dev-insecure-secret-change-me";
}

export function credentials(): { username: string; password: string } {
  return { username: process.env.AUTH_USERNAME || "b24", password: process.env.AUTH_PASSWORD || "" };
}

/** True when login is effectively disabled because no password is configured. */
export function authDisabled(): boolean {
  return !process.env.AUTH_PASSWORD;
}

function sign(value: string): string {
  return crypto.createHmac("sha256", secret()).update(value).digest("base64url");
}

export function verifyCredentials(username: string, password: string): boolean {
  const c = credentials();
  if (!c.password) return true; // not configured: allow (dev)
  const a = Buffer.from(username);
  const b = Buffer.from(c.username);
  const userOk = a.length === b.length && crypto.timingSafeEqual(a, b);
  const p = Buffer.from(password);
  const q = Buffer.from(c.password);
  const passOk = p.length === q.length && crypto.timingSafeEqual(p, q);
  return userOk && passOk;
}

/** Stateless signed token: "<username>.<expiryMs>.<hmac>". Lets any number of people share one login. */
export function issueToken(username: string, ttlHours = DEFAULT_TTL_HOURS): { token: string; maxAge: number } {
  const exp = Date.now() + ttlHours * 3600_000;
  const payload = `${Buffer.from(username).toString("base64url")}.${exp}`;
  return { token: `${payload}.${sign(payload)}`, maxAge: ttlHours * 3600 };
}

export function verifyToken(token: string | undefined): { username: string } | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const payload = `${parts[0]}.${parts[1]}`;
  const expected = sign(payload);
  const a = Buffer.from(parts[2]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (Number(parts[1]) < Date.now()) return null;
  try {
    return { username: Buffer.from(parts[0], "base64url").toString() };
  } catch {
    return null;
  }
}
