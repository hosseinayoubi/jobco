-- Initial schema for Neon/Postgres
-- You can regenerate via: npx prisma migrate dev --name init

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS "User" (
  "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  "email" text NOT NULL UNIQUE,
  "name" text,
  "passwordHash" text,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS "UserProfile" (
  "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  "userId" uuid NOT NULL UNIQUE REFERENCES "User"("id") ON DELETE CASCADE,
  "fullName" text,
  "headline" text,
  "phone" text,
  "location" text,
  "resumeText" text,
  "cvFileUrl" text,
  "linkedinUrl" text,
  "parsedSkills" jsonb,
  "experienceLevel" text,
  "targetLocation" text,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS "JobApplication" (
  "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  "userId" uuid NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "title" text NOT NULL,
  "company" text NOT NULL,
  "location" text,
  "url" text,
  "matchPercent" int,
  "reasoning" text,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "JobApplication_userId_createdAt_idx" ON "JobApplication"("userId","createdAt" DESC);
