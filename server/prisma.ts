import { PrismaClient } from "@prisma/client";

declare global {
  var __prisma: PrismaClient | undefined;
}

export const prisma =
  global.__prisma ??
  new PrismaClient({
    log: ["error"],
    datasources: {
      db: {
        url: process.env.DATABASE_URL,
      },
    },
  });

global.__prisma = prisma;

// Keep connection alive
prisma.$connect().catch((e) => {
  console.error("Prisma connect error:", e);
});
