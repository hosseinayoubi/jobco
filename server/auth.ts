import type { Request, Response, NextFunction } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { storage } from "./storage";

export const AuthUserSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  name: z.string().nullable().optional(),
});
export type AuthUser = z.infer<typeof AuthUserSchema>;

const JWT_COOKIE_NAME = "gnt_token";
const JWT_TTL_SECONDS = 60 * 60 * 24 * 14; // 14 days

function getJwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error("Missing JWT_SECRET env var");
  return s;
}

function isProd() {
  return process.env.NODE_ENV === "production";
}

export function signAuthToken(user: AuthUser) {
  const secret = getJwtSecret();
  return jwt.sign(
    { sub: user.id, email: user.email, name: user.name ?? null },
    secret,
    { expiresIn: JWT_TTL_SECONDS }
  );
}

export function setAuthCookie(res: Response, token: string) {
  res.cookie(JWT_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProd(),
    sameSite: "lax",
    path: "/",
    maxAge: JWT_TTL_SECONDS * 1000,
  });
}

export function clearAuthCookie(res: Response) {
  res.cookie(JWT_COOKIE_NAME, "", {
    httpOnly: true,
    secure: isProd(),
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
}

export function getAuthedUser(req: Request): AuthUser {
  const u = (req as any).user as AuthUser | undefined;
  if (!u) throw new Error("Not authenticated");
  return u;
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const token =
      (req as any).cookies?.[JWT_COOKIE_NAME] ||
      (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();

    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const secret = getJwtSecret();
    const payload = jwt.verify(token, secret) as any;

    const user: AuthUser = {
      id: String(payload.sub),
      email: String(payload.email || ""),
      name: payload.name ?? null,
    };

    AuthUserSchema.parse(user);
    (req as any).user = user;
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

export async function registerWithEmailPassword(input: { email: string; password: string; name?: string }) {
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");
  const name = input.name ? String(input.name).trim() : null;

  if (!email || !password) throw new Error("Email and password are required");

  const existing = await storage.getUserByEmail(email);
  if (existing) throw new Error("Email already registered");

  const passwordHash = await bcrypt.hash(password, 10);
  const created = await storage.createUser({ email, name, passwordHash });

  return { id: created.id, email: created.email, name: created.name ?? null } satisfies AuthUser;
}

export async function loginWithEmailPassword(input: { email: string; password: string }) {
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");

  if (!email || !password) throw new Error("Email and password are required");

  const user = await storage.getUserByEmail(email);
  if (!user || !user.passwordHash) throw new Error("Invalid credentials");

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) throw new Error("Invalid credentials");

  return { id: user.id, email: user.email, name: user.name ?? null } satisfies AuthUser;
}
