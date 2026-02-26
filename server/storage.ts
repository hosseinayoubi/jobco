import { prisma } from "./prisma";
import bcrypt from "bcryptjs";

export const storage = {
  // =========================
  // AUTH USERS
  // =========================
  async getUserByEmail(email: string) {
    const u = await prisma.user.findUnique({
      where: { email: email.trim().toLowerCase() },
    });
    if (!u) return null;
    return {
      id: u.id,
      email: u.email,
      name: u.name,
      passwordHash: u.passwordHash,
    };
  },

  async getUserById(id: string) {
    const u = await prisma.user.findUnique({ where: { id } });
    if (!u) return null;
    return {
      id: u.id,
      email: u.email,
      name: u.name,
      passwordHash: u.passwordHash,
    };
  },

  async createUser(input: { email: string; name: string | null; passwordHash: string | null }) {
    const email = String(input.email || "").trim().toLowerCase();
    const name = input.name == null ? null : String(input.name).trim();
    const passwordHash = input.passwordHash == null ? null : String(input.passwordHash).trim();
    if (!email) throw new Error("Email is required");

    const created = await prisma.user.create({
      data: { email, name, passwordHash },
      select: { id: true, email: true, name: true, passwordHash: true },
    });

    return {
      id: created.id,
      email: created.email,
      name: created.name,
      passwordHash: created.passwordHash,
    };
  },

  // =========================
  // PROFILE
  // =========================
  async getUserProfile(userId: string) {
    const p = await prisma.userProfile.findUnique({ where: { userId } });
    if (!p) return null;

    return {
      userId: p.userId,
      fullName: p.fullName ?? null,
      headline: p.headline ?? null,
      phone: p.phone ?? null,
      location: p.location ?? null,
      resumeText: p.resumeText ?? null,
      cvFileUrl: p.cvFileUrl ?? null,
      linkedinUrl: p.linkedinUrl ?? null,
      parsedSkills: (p.parsedSkills as any) ?? [],
      experienceLevel: p.experienceLevel ?? null,
      targetLocation: p.targetLocation ?? null,
      updatedAt: p.updatedAt.toISOString(),
    };
  },

  async upsertUserProfile(userId: string, updates: any) {
    const data: any = {
      fullName: updates.fullName ?? undefined,
      headline: updates.headline ?? undefined,
      phone: updates.phone ?? undefined,
      location: updates.location ?? undefined,
      resumeText: updates.resumeText ?? undefined,
      cvFileUrl: updates.cvFileUrl ?? undefined,
      linkedinUrl: updates.linkedinUrl ?? undefined,
      parsedSkills: updates.parsedSkills ?? undefined,
      experienceLevel: updates.experienceLevel ?? undefined,
      targetLocation: updates.targetLocation ?? undefined,
    };

    const p = await prisma.userProfile.upsert({
      where: { userId },
      create: { userId, ...data },
      update: data,
    });

    return {
      userId: p.userId,
      fullName: p.fullName ?? null,
      headline: p.headline ?? null,
      phone: p.phone ?? null,
      location: p.location ?? null,
      resumeText: p.resumeText ?? null,
      cvFileUrl: p.cvFileUrl ?? null,
      linkedinUrl: p.linkedinUrl ?? null,
      parsedSkills: (p.parsedSkills as any) ?? [],
      experienceLevel: p.experienceLevel ?? null,
      targetLocation: p.targetLocation ?? null,
      updatedAt: p.updatedAt.toISOString(),
    };
  },

  // =========================
  // JOBS: SAVE / LIST
  // =========================
  async saveJobApplication(userId: string, body: any) {
    const createdAt = body.createdAt ? new Date(body.createdAt) : undefined;

    if (body.id) {
      const ja = await prisma.jobApplication.update({
        where: { id: body.id },
        data: {
          title: body.title,
          company: body.company,
          location: body.location ?? null,
          url: body.url ?? null,
          matchPercent: body.matchPercent == null ? null : Math.round(body.matchPercent),
          reasoning: body.reasoning ?? null,
        },
      });

      return {
        id: ja.id,
        title: ja.title,
        company: ja.company,
        location: ja.location ?? undefined,
        url: ja.url ?? undefined,
        matchPercent: ja.matchPercent ?? undefined,
        reasoning: ja.reasoning ?? undefined,
        createdAt: ja.createdAt.toISOString(),
      };
    }

    const ja = await prisma.jobApplication.create({
      data: {
        userId,
        title: body.title,
        company: body.company,
        location: body.location ?? null,
        url: body.url ?? null,
        matchPercent: body.matchPercent == null ? null : Math.round(body.matchPercent),
        reasoning: body.reasoning ?? null,
        createdAt: createdAt ?? undefined,
      },
    });

    return {
      id: ja.id,
      title: ja.title,
      company: ja.company,
      location: ja.location ?? undefined,
      url: ja.url ?? undefined,
      matchPercent: ja.matchPercent ?? undefined,
      reasoning: ja.reasoning ?? undefined,
      createdAt: ja.createdAt.toISOString(),
    };
  },

  async listSavedJobs(userId: string) {
    const rows = await prisma.jobApplication.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
      take: 200,
    });

    return rows.map((ja) => ({
      id: ja.id,
      title: ja.title,
      company: ja.company,
      location: ja.location ?? undefined,
      url: ja.url ?? undefined,
      matchPercent: ja.matchPercent ?? undefined,
      reasoning: ja.reasoning ?? undefined,
      createdAt: ja.createdAt.toISOString(),
    }));
  },
};
