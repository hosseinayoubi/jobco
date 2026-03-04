import serverless from "serverless-http";
import express, { type Request, type Response } from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import pdfParse from "pdf-parse";
import mammoth from "mammoth";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";

// ─── Prisma ──────────────────────────────────────────────────────────────────
declare global { var __prisma: PrismaClient | undefined; }
const prisma = global.__prisma ?? new PrismaClient({ log: ["error"] });
global.__prisma = prisma;

// ─── Schemas ─────────────────────────────────────────────────────────────────
const RegisterInput = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
  name: z.string().min(1).max(200).optional(),
});
const LoginInput = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(128),
});
const AuthUser = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  name: z.string().nullable().optional(),
});
type AuthUserType = z.infer<typeof AuthUser>;

// ─── JWT helpers ─────────────────────────────────────────────────────────────
const JWT_COOKIE = "gnt_token";
const JWT_TTL = 60 * 60 * 24 * 14;

function getSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error("Missing JWT_SECRET");
  return s;
}
function isProd() { return process.env.NODE_ENV === "production"; }

function signToken(user: AuthUserType) {
  return jwt.sign(
    { sub: user.id, email: user.email, name: user.name ?? null },
    getSecret(),
    { expiresIn: JWT_TTL }
  );
}
function setCookie(res: Response, token: string) {
  res.cookie(JWT_COOKIE, token, {
    httpOnly: true, secure: isProd(), sameSite: "lax", path: "/", maxAge: JWT_TTL * 1000,
  });
}
function clearCookie(res: Response) {
  res.cookie(JWT_COOKIE, "", { httpOnly: true, secure: isProd(), sameSite: "lax", path: "/", maxAge: 0 });
}

function requireAuth(req: any, res: any, next: any) {
  try {
    const token =
      req.cookies?.[JWT_COOKIE] ||
      (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    const payload = jwt.verify(token, getSecret()) as any;
    req.user = { id: String(payload.sub), email: String(payload.email || ""), name: payload.name ?? null };
    AuthUser.parse(req.user);
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

// ─── Storage helpers ──────────────────────────────────────────────────────────
async function getUserByEmail(email: string) {
  const u = await prisma.user.findUnique({ where: { email: email.trim().toLowerCase() } });
  if (!u) return null;
  return { id: u.id, email: u.email, name: u.name, passwordHash: u.passwordHash };
}
async function createUser(input: { email: string; name: string | null; passwordHash: string | null }) {
  const u = await prisma.user.create({
    data: { email: input.email.trim().toLowerCase(), name: input.name, passwordHash: input.passwordHash },
    select: { id: true, email: true, name: true, passwordHash: true },
  });
  return u;
}

// ─── App ─────────────────────────────────────────────────────────────────────
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get("/api/healthz", (_req, res) => res.json({ ok: true }));

// ─── Google OAuth ─────────────────────────────────────────────────────────────
const G_ID = process.env.GOOGLE_CLIENT_ID;
const G_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const G_CB = process.env.GOOGLE_CALLBACK_URL || "https://jobco.weomeo.win/api/auth/google/callback";

if (G_ID && G_SECRET) {
  passport.use(new GoogleStrategy(
    { clientID: G_ID, clientSecret: G_SECRET, callbackURL: G_CB },
    async (_at, _rt, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value?.trim().toLowerCase() ?? null;
        const name = profile.displayName || null;
        if (!email) return done(new Error("No email from Google"), undefined as any);
        let user = await getUserByEmail(email);
        if (!user) user = await createUser({ email, name, passwordHash: null });
        return done(null, { id: user.id, email: user.email, name: user.name ?? null });
      } catch (e: any) { return done(e, undefined as any); }
    }
  ));
  app.use(passport.initialize());
  app.get("/api/auth/google", passport.authenticate("google", { scope: ["profile", "email"], session: false }));
  app.get("/api/auth/google/callback",
    passport.authenticate("google", { session: false, failureRedirect: "/login?error=google" }),
    (req: any, res: Response) => {
      try {
        const token = signToken(req.user as AuthUserType);
        setCookie(res, token);
        res.redirect("/dashboard");
      } catch { res.redirect("/login?error=token"); }
    }
  );
} else {
  app.get("/api/auth/google", (_req, res) => res.status(501).json({ error: "Google OAuth not configured" }));
  app.get("/api/auth/google/callback", (_req, res) => res.redirect("/login?error=google_not_configured"));
}

// ─── Auth routes ──────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req: Request, res: Response) => {
  try {
    const { email, password, name } = RegisterInput.parse(req.body);
    const existing = await getUserByEmail(email);
    if (existing) return res.status(400).json({ error: "Email already registered" });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await createUser({ email, name: name || null, passwordHash });
    const token = signToken({ id: user.id, email: user.email, name: user.name ?? null });
    setCookie(res, token);
    return res.json({ id: user.id, email: user.email, name: user.name ?? null });
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Register failed" }); }
});

app.post("/api/auth/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = LoginInput.parse(req.body);
    const user = await getUserByEmail(email);
    if (!user || !user.passwordHash) return res.status(400).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });
    const token = signToken({ id: user.id, email: user.email, name: user.name ?? null });
    setCookie(res, token);
    return res.json({ id: user.id, email: user.email, name: user.name ?? null });
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Login failed" }); }
});

app.post("/api/auth/logout", (_req: any, res: any) => { clearCookie(res); res.json({ ok: true }); });

app.get("/api/auth/me", requireAuth, (req: any, res: any) => res.json(req.user));

// ─── Profile ──────────────────────────────────────────────────────────────────
app.get("/api/profile", requireAuth, async (req: any, res: any) => {
  try {
    const p = await prisma.userProfile.findUnique({ where: { userId: req.user.id } });
    if (!p) return res.json(null);
    return res.json({
      userId: p.userId, fullName: p.fullName ?? null, headline: p.headline ?? null,
      phone: p.phone ?? null, location: p.location ?? null, resumeText: p.resumeText ?? null,
      cvFileUrl: p.cvFileUrl ?? null, linkedinUrl: p.linkedinUrl ?? null,
      parsedSkills: (p.parsedSkills as any) ?? [], experienceLevel: p.experienceLevel ?? null,
      targetLocation: p.targetLocation ?? null, updatedAt: p.updatedAt.toISOString(),
    });
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Failed to load profile" }); }
});

app.patch("/api/profile", requireAuth, async (req: any, res: any) => {
  try {
    const data: any = {};
    const b = req.body || {};
    const fields = ["fullName","headline","phone","location","resumeText","cvFileUrl","linkedinUrl","parsedSkills","experienceLevel","targetLocation"];
    for (const f of fields) if (b[f] !== undefined) data[f] = b[f];
    const p = await prisma.userProfile.upsert({
      where: { userId: req.user.id },
      create: { userId: req.user.id, ...data },
      update: data,
    });
    return res.json({
      userId: p.userId, fullName: p.fullName ?? null, headline: p.headline ?? null,
      phone: p.phone ?? null, location: p.location ?? null, resumeText: p.resumeText ?? null,
      cvFileUrl: p.cvFileUrl ?? null, linkedinUrl: p.linkedinUrl ?? null,
      parsedSkills: (p.parsedSkills as any) ?? [], experienceLevel: p.experienceLevel ?? null,
      targetLocation: p.targetLocation ?? null, updatedAt: p.updatedAt.toISOString(),
    });
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Profile update failed" }); }
});

// ─── CV Upload ────────────────────────────────────────────────────────────────
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1 * 1024 * 1024 } });

async function extractText(file: Express.Multer.File) {
  const n = (file.originalname || "").toLowerCase();
  if (n.endsWith(".pdf")) { const o = await pdfParse(file.buffer); return (o.text || "").trim(); }
  if (n.endsWith(".docx")) { const o = await mammoth.extractRawText({ buffer: file.buffer }); return (o.value || "").trim(); }
  if (n.endsWith(".txt")) return file.buffer.toString("utf8").trim();
  const t = file.buffer.toString("utf8").trim();
  if (t.length > 30) return t;
  throw new Error("Unsupported file type. Please upload .pdf, .docx, or .txt.");
}

app.post("/api/profile/upload-cv", requireAuth, (req: any, res: any) => {
  upload.single("file")(req, res, async (err: any) => {
    try {
      if (err) return res.status(400).json({ error: err?.message || "Upload failed" });
      const file = req.file as Express.Multer.File | undefined;
      if (!file) return res.status(400).json({ error: "No file" });
      const text = await extractText(file);
      if (!text || text.length < 10) return res.status(400).json({ error: "Could not extract text." });
      const p = await prisma.userProfile.upsert({
        where: { userId: req.user.id },
        create: { userId: req.user.id, resumeText: text, cvFileUrl: null },
        update: { resumeText: text, cvFileUrl: null },
      });
      return res.json({ ok: true, filename: file.originalname, text, profile: p });
    } catch (e: any) { return res.status(400).json({ error: e?.message || "Upload failed" }); }
  });
});

app.post("/api/profile/analyze-cv", requireAuth, async (req: any, res: any) => {
  try {
    const { cvText } = req.body;
    if (!cvText || cvText.length < 50) return res.status(400).json({ error: "CV text too short" });
    const { default: OpenAI } = await import("openai");
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const model = process.env.OPENAI_MODEL || "gpt-4o-mini";
    const resp = await openai.chat.completions.create({
      model,
      messages: [{ role: "user", content: `Analyze this CV and return JSON with: summary, skills (array), roles (array), seniority (intern/junior/mid/senior/lead/unknown), suggestedHeadline, keywords (array).\n\nCV:\n${cvText.slice(0, 6000)}` }],
      response_format: { type: "json_object" },
    });
    const raw = resp.choices[0]?.message?.content || "{}";
    return res.json(JSON.parse(raw));
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Analyze failed" }); }
});

// ─── Jobs ─────────────────────────────────────────────────────────────────────
app.post("/api/jobs/search", requireAuth, async (req: any, res: any) => {
  try {
    const { query, location, resumeText } = req.body;
    const { default: axios } = await import("axios");
    const key = process.env.SERPER_API_KEY;
    if (!key) return res.status(500).json({ error: "SERPER_API_KEY missing" });
    const q = (query && query !== "auto") ? query : (resumeText ? resumeText.slice(0, 100) : "software engineer");
    const r = await axios.post("https://google.serper.dev/search",
      { q: `${q} site:linkedin.com/jobs OR site:indeed.com job`, gl: "gb", hl: "en", num: 10 },
      { headers: { "X-API-KEY": key, "Content-Type": "application/json" }, timeout: 15000 }
    );
    const results = (r.data?.organic || []).slice(0, 10).map((x: any) => ({
      title: x.title || "Untitled", company: (x.title || "").split(" - ").pop() || "Unknown",
      location: location || "Worldwide", description: x.snippet || "", url: x.link || "",
    }));
    return res.json(results);
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Search failed" }); }
});

app.post("/api/jobs/match", requireAuth, async (req: any, res: any) => {
  try {
    const { jobDescription } = req.body;
    const { default: OpenAI } = await import("openai");
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const model = process.env.OPENAI_MODEL || "gpt-4o-mini";
    const resp = await openai.chat.completions.create({
      model,
      messages: [{ role: "user", content: `Analyze this job vs candidate and return JSON with: matchPercentage (0-100), matchingSkills (array), missingSkills (array), analysis (string), strengths (array), gaps (array), recommendedKeywords (array), salaryRange (string), seniorityFit (perfect/good/average/poor).\n\n${jobDescription?.slice(0, 4000)}` }],
      response_format: { type: "json_object" },
    });
    const raw = resp.choices[0]?.message?.content || "{}";
    return res.json(JSON.parse(raw));
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Match failed" }); }
});

app.post("/api/jobs/generate", requireAuth, async (req: any, res: any) => {
  try {
    const { jobTitle, companyName, combinedText } = req.body;
    const { default: OpenAI } = await import("openai");
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const model = process.env.OPENAI_MODEL || "gpt-4o-mini";
    const resp = await openai.chat.completions.create({
      model,
      messages: [{ role: "user", content: `Generate application materials for this job. Return JSON with: customCv (string), coverLetter (string), interviewQa (array of {q, a, type}).\n\nJob: ${jobTitle} at ${companyName}\n\n${combinedText?.slice(0, 5000)}` }],
      response_format: { type: "json_object" },
    });
    const raw = resp.choices[0]?.message?.content || "{}";
    return res.json(JSON.parse(raw));
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Generate failed" }); }
});

app.post("/api/jobs/save", requireAuth, async (req: any, res: any) => {
  try {
    const b = req.body;
    const ja = await prisma.jobApplication.create({
      data: { userId: req.user.id, title: b.title, company: b.company, location: b.location ?? null, url: b.url ?? null, matchPercent: b.matchPercent ? Math.round(b.matchPercent) : null, reasoning: b.reasoning ?? null },
    });
    return res.status(201).json({ id: ja.id, title: ja.title, company: ja.company });
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Save failed" }); }
});

app.get("/api/jobs/saved", requireAuth, async (req: any, res: any) => {
  try {
    const rows = await prisma.jobApplication.findMany({ where: { userId: req.user.id }, orderBy: { createdAt: "desc" }, take: 200 });
    return res.json(rows.map((j: any) => ({ id: j.id, title: j.title, company: j.company, location: j.location, url: j.url, matchPercent: j.matchPercent, createdAt: j.createdAt.toISOString() })));
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Failed" }); }
});

// ─── PDF ──────────────────────────────────────────────────────────────────────
app.post("/api/pdf", requireAuth, async (req: any, res: any) => {
  try {
    const { title, content, filename } = req.body;
    const { default: PDFDocument } = await import("pdfkit");
    const doc = new PDFDocument({ size: "A4", margins: { top: 54, left: 54, right: 54, bottom: 60 } });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    const done = new Promise<Buffer>((resolve, reject) => {
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);
    });
    if (title) { doc.fontSize(18).font("Helvetica-Bold").text(String(title), { align: "left" }).moveDown(0.5); }
    doc.fontSize(11).font("Helvetica").text(String(content || ""), { lineGap: 4 });
    doc.end();
    const buf = await done;
    const fname = (filename || "document.pdf").replace(/[/\\"]/g, "_");
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${fname}"`);
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(buf);
  } catch (e: any) { return res.status(500).json({ error: e?.message || "PDF failed" }); }
});

export default serverless(app);
