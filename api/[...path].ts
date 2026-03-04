import serverless from "serverless-http";
import express, { type Request, type Response } from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import pdfParse from "pdf-parse";
import mammoth from "mammoth";
import pg from "pg";
import { z } from "zod";
import OpenAI from "openai";
import axios from "axios";
import PDFDocument from "pdfkit";

// ─── DB (pg مستقیم - بدون Prisma) ────────────────────────────────────────────
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 1,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000,
  ssl: { rejectUnauthorized: false },
});

async function query(sql: string, params: any[] = []) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

// ─── JWT ──────────────────────────────────────────────────────────────────────
const JWT_COOKIE = "gnt_token";
const JWT_TTL = 60 * 60 * 24 * 14;

function getSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error("Missing JWT_SECRET");
  return s;
}
function isProd() { return process.env.NODE_ENV === "production"; }

function signToken(user: { id: string; email: string; name?: string | null }) {
  return jwt.sign({ sub: user.id, email: user.email, name: user.name ?? null }, getSecret(), { expiresIn: JWT_TTL });
}
function setCookie(res: Response, token: string) {
  res.cookie(JWT_COOKIE, token, { httpOnly: true, secure: isProd(), sameSite: "lax", path: "/", maxAge: JWT_TTL * 1000 });
}
function clearCookie(res: Response) {
  res.cookie(JWT_COOKIE, "", { httpOnly: true, secure: isProd(), sameSite: "lax", path: "/", maxAge: 0 });
}
function requireAuth(req: any, res: any, next: any) {
  try {
    const token = req.cookies?.[JWT_COOKIE] || (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    const payload = jwt.verify(token, getSecret()) as any;
    req.user = { id: String(payload.sub), email: String(payload.email || ""), name: payload.name ?? null };
    return next();
  } catch { return res.status(401).json({ error: "Unauthorized" }); }
}

// ─── DB Helpers ───────────────────────────────────────────────────────────────
async function getUserByEmail(email: string) {
  const r = await query(`SELECT id, email, name, "passwordHash" FROM "User" WHERE email=$1 LIMIT 1`, [email.trim().toLowerCase()]);
  return r.rows[0] || null;
}
async function getUserById(id: string) {
  const r = await query(`SELECT id, email, name FROM "User" WHERE id=$1 LIMIT 1`, [id]);
  return r.rows[0] || null;
}
async function createUser(input: { email: string; name: string | null; passwordHash: string | null }) {
  const r = await query(
    `INSERT INTO "User" (id, email, name, "passwordHash", "createdAt", "updatedAt") VALUES (gen_random_uuid(), $1, $2, $3, now(), now()) RETURNING id, email, name`,
    [input.email.trim().toLowerCase(), input.name, input.passwordHash]
  );
  return r.rows[0];
}

function getOpenAI() { return new OpenAI({ apiKey: process.env.OPENAI_API_KEY }); }
function getModel() { return process.env.OPENAI_MODEL || "gpt-4o-mini"; }

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get("/api/healthz", async (_req, res) => {
  try {
    await query("SELECT 1");
    return res.json({ ok: true, db: "connected" });
  } catch (e: any) {
    return res.status(500).json({ ok: false, db: "error", error: e?.message });
  }
});

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req: Request, res: Response) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const name = req.body.name ? String(req.body.name).trim() : null;
    if (!email || !password || password.length < 8) return res.status(400).json({ error: "Invalid input" });
    const existing = await getUserByEmail(email);
    if (existing) return res.status(400).json({ error: "Email already registered" });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await createUser({ email, name, passwordHash });
    const token = signToken(user);
    setCookie(res, token);
    return res.json({ id: user.id, email: user.email, name: user.name ?? null });
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Register failed" }); }
});

app.post("/api/auth/login", async (req: Request, res: Response) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
    const user = await getUserByEmail(email);
    if (!user || !user.passwordHash) return res.status(400).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });
    const token = signToken(user);
    setCookie(res, token);
    return res.json({ id: user.id, email: user.email, name: user.name ?? null });
  } catch (e: any) { return res.status(400).json({ error: e?.message || "Login failed" }); }
});

app.post("/api/auth/logout", (_req: any, res: any) => { clearCookie(res); res.json({ ok: true }); });

app.get("/api/auth/me", requireAuth, async (req: any, res: any) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) return res.status(401).json({ error: "User not found" });
    return res.json({ id: user.id, email: user.email, name: user.name ?? null });
  } catch (e: any) { return res.status(500).json({ error: e?.message }); }
});

// ─── Google OAuth ─────────────────────────────────────────────────────────────
app.get("/api/auth/google", (_req, res) => {
  const G_ID = process.env.GOOGLE_CLIENT_ID;
  const G_CB = process.env.GOOGLE_CALLBACK_URL || "https://jobco.weomeo.win/api/auth/google/callback";
  if (!G_ID) return res.status(501).json({ error: "Google OAuth not configured" });
  const params = new URLSearchParams({ client_id: G_ID, redirect_uri: G_CB, response_type: "code", scope: "openid email profile", access_type: "offline" });
  return res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get("/api/auth/google/callback", async (req: any, res: any) => {
  try {
    const { code } = req.query;
    const G_ID = process.env.GOOGLE_CLIENT_ID;
    const G_SECRET = process.env.GOOGLE_CLIENT_SECRET;
    const G_CB = process.env.GOOGLE_CALLBACK_URL || "https://jobco.weomeo.win/api/auth/google/callback";
    if (!code || !G_ID || !G_SECRET) return res.redirect("/login?error=google");
    const tokenRes = await axios.post("https://oauth2.googleapis.com/token", { code, client_id: G_ID, client_secret: G_SECRET, redirect_uri: G_CB, grant_type: "authorization_code" });
    const idToken = tokenRes.data.id_token;
    const parts = idToken.split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    const email = payload.email?.trim().toLowerCase();
    const name = payload.name || null;
    if (!email) return res.redirect("/login?error=google_no_email");
    let user = await getUserByEmail(email);
    if (!user) user = await createUser({ email, name, passwordHash: null });
    const token = signToken(user);
    setCookie(res, token);
    return res.redirect("/dashboard");
  } catch (e: any) { return res.redirect("/login?error=google_failed"); }
});

// ─── Profile ──────────────────────────────────────────────────────────────────
app.get("/api/profile", requireAuth, async (req: any, res: any) => {
  try {
    const r = await query(`SELECT * FROM "UserProfile" WHERE "userId"=$1 LIMIT 1`, [req.user.id]);
    if (!r.rows[0]) return res.json(null);
    const p = r.rows[0];
    return res.json({ userId: p.userId, fullName: p.fullName, headline: p.headline, phone: p.phone, location: p.location, resumeText: p.resumeText, cvFileUrl: p.cvFileUrl, linkedinUrl: p.linkedinUrl, parsedSkills: p.parsedSkills ?? [], experienceLevel: p.experienceLevel, targetLocation: p.targetLocation, updatedAt: p.updatedAt });
  } catch (e: any) { return res.status(400).json({ error: e?.message }); }
});

app.patch("/api/profile", requireAuth, async (req: any, res: any) => {
  try {
    const b = req.body || {};
    const fields = ["fullName","headline","phone","location","resumeText","cvFileUrl","linkedinUrl","parsedSkills","experienceLevel","targetLocation"];
    const sets: string[] = [];
    const vals: any[] = [];
    let i = 1;
    for (const f of fields) {
      if (b[f] !== undefined) { sets.push(`"${f}"=$${i++}`); vals.push(b[f]); }
    }
    vals.push(req.user.id);
    if (sets.length === 0) {
      await query(`INSERT INTO "UserProfile" (id, "userId", "updatedAt", "createdAt") VALUES (gen_random_uuid(), $1, now(), now()) ON CONFLICT ("userId") DO NOTHING`, [req.user.id]);
    } else {
      await query(`INSERT INTO "UserProfile" (id, "userId", ${sets.map((s,i) => s.split("=")[0]).join(",")}, "updatedAt", "createdAt") VALUES (gen_random_uuid(), $${i}, ${vals.slice(0,-1).map((_,j) => `$${j+1}`).join(",")}, now(), now()) ON CONFLICT ("userId") DO UPDATE SET ${sets.join(", ")}, "updatedAt"=now()`, vals);
    }
    const r = await query(`SELECT * FROM "UserProfile" WHERE "userId"=$1 LIMIT 1`, [req.user.id]);
    const p = r.rows[0] || {};
    return res.json({ userId: p.userId, fullName: p.fullName, headline: p.headline, phone: p.phone, location: p.location, resumeText: p.resumeText, cvFileUrl: p.cvFileUrl, linkedinUrl: p.linkedinUrl, parsedSkills: p.parsedSkills ?? [], experienceLevel: p.experienceLevel, targetLocation: p.targetLocation, updatedAt: p.updatedAt });
  } catch (e: any) { return res.status(400).json({ error: e?.message }); }
});

// ─── CV Upload ────────────────────────────────────────────────────────────────
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 } });

app.post("/api/profile/upload-cv", requireAuth, (req: any, res: any) => {
  upload.single("file")(req, res, async (err: any) => {
    try {
      if (err) return res.status(400).json({ error: err?.message });
      const file = req.file as Express.Multer.File | undefined;
      if (!file) return res.status(400).json({ error: "No file" });
      const n = file.originalname.toLowerCase();
      let text = "";
      if (n.endsWith(".pdf")) { const o = await pdfParse(file.buffer); text = o.text?.trim() || ""; }
      else if (n.endsWith(".docx")) { const o = await mammoth.extractRawText({ buffer: file.buffer }); text = o.value?.trim() || ""; }
      else text = file.buffer.toString("utf8").trim();
      if (text.length < 10) return res.status(400).json({ error: "Could not extract text." });
      await query(`INSERT INTO "UserProfile" (id, "userId", "resumeText", "updatedAt", "createdAt") VALUES (gen_random_uuid(), $1, $2, now(), now()) ON CONFLICT ("userId") DO UPDATE SET "resumeText"=$2, "updatedAt"=now()`, [req.user.id, text]);
      return res.json({ ok: true, filename: file.originalname, text });
    } catch (e: any) { return res.status(400).json({ error: e?.message }); }
  });
});

app.post("/api/profile/analyze-cv", requireAuth, async (req: any, res: any) => {
  try {
    const { cvText } = req.body;
    if (!cvText || cvText.length < 50) return res.status(400).json({ error: "CV text too short" });
    const resp = await getOpenAI().chat.completions.create({ model: getModel(), messages: [{ role: "user", content: `Analyze this CV and return JSON with: summary, skills (array), roles (array), seniority (intern/junior/mid/senior/lead/unknown), suggestedHeadline, keywords (array).\n\nCV:\n${cvText.slice(0, 6000)}` }], response_format: { type: "json_object" } });
    return res.json(JSON.parse(resp.choices[0]?.message?.content || "{}"));
  } catch (e: any) { return res.status(400).json({ error: e?.message }); }
});

// ─── Jobs ─────────────────────────────────────────────────────────────────────
app.post("/api/jobs/search", requireAuth, async (req: any, res: any) => {
  try {
    const { query: q, location, resumeText } = req.body;
    const key = process.env.SERPER_API_KEY;
    if (!key) return res.status(500).json({ error: "SERPER_API_KEY missing" });
    const sq = (q && q !== "auto") ? q : (resumeText ? resumeText.slice(0, 80) : "software engineer");
    const r = await axios.post("https://google.serper.dev/search", { q: `${sq} job UK`, gl: "gb", hl: "en", num: 10 }, { headers: { "X-API-KEY": key, "Content-Type": "application/json" }, timeout: 15000 });
    const results = (r.data?.organic || []).slice(0, 10).map((x: any) => ({ title: x.title || "Untitled", company: (x.title || "").split(" - ").pop() || "Unknown", location: location || "UK", description: x.snippet || "", url: x.link || "" }));
    return res.json(results);
  } catch (e: any) { return res.status(400).json({ error: e?.message }); }
});

app.post("/api/jobs/match", requireAuth, async (req: any, res: any) => {
  try {
    const { jobDescription } = req.body;
    const resp = await getOpenAI().chat.completions.create({ model: getModel(), messages: [{ role: "user", content: `Analyze this job vs candidate and return JSON with: matchPercentage (0-100), matchingSkills (array), missingSkills (array), analysis (string), strengths (array), gaps (array), recommendedKeywords (array), salaryRange (string), seniorityFit (perfect/good/average/poor).\n\n${(jobDescription || "").slice(0, 4000)}` }], response_format: { type: "json_object" } });
    return res.json(JSON.parse(resp.choices[0]?.message?.content || "{}"));
  } catch (e: any) { return res.status(400).json({ error: e?.message }); }
});

app.post("/api/jobs/generate", requireAuth, async (req: any, res: any) => {
  try {
    const { jobTitle, companyName, combinedText } = req.body;
    const resp = await getOpenAI().chat.completions.create({ model: getModel(), messages: [{ role: "user", content: `Generate job application materials. Return JSON with: customCv (string), coverLetter (string), interviewQa (array of {q, a, type: "general"|"technical"}).\n\nJob: ${jobTitle} at ${companyName}\n\n${(combinedText || "").slice(0, 5000)}` }], response_format: { type: "json_object" } });
    return res.json(JSON.parse(resp.choices[0]?.message?.content || "{}"));
  } catch (e: any) { return res.status(400).json({ error: e?.message }); }
});

app.post("/api/jobs/save", requireAuth, async (req: any, res: any) => {
  try {
    const b = req.body;
    const r = await query(`INSERT INTO "JobApplication" (id, "userId", title, company, location, url, "matchPercent", reasoning, "createdAt", "updatedAt") VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, now(), now()) RETURNING id, title, company, "createdAt"`, [req.user.id, b.title, b.company, b.location ?? null, b.url ?? null, b.matchPercent ? Math.round(b.matchPercent) : null, b.reasoning ?? null]);
    return res.status(201).json(r.rows[0]);
  } catch (e: any) { return res.status(400).json({ error: e?.message }); }
});

app.get("/api/jobs/saved", requireAuth, async (req: any, res: any) => {
  try {
    const r = await query(`SELECT id, title, company, location, url, "matchPercent", reasoning, "createdAt" FROM "JobApplication" WHERE "userId"=$1 ORDER BY "createdAt" DESC LIMIT 200`, [req.user.id]);
    return res.json(r.rows);
  } catch (e: any) { return res.status(400).json({ error: e?.message }); }
});

// ─── PDF ──────────────────────────────────────────────────────────────────────
app.post("/api/pdf", requireAuth, async (req: any, res: any) => {
  try {
    const { title, content, filename } = req.body;
    const doc = new PDFDocument({ size: "A4", margins: { top: 54, left: 54, right: 54, bottom: 60 } });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    const done = new Promise<Buffer>((resolve, reject) => { doc.on("end", () => resolve(Buffer.concat(chunks))); doc.on("error", reject); });
    if (title) doc.fontSize(18).font("Helvetica-Bold").text(String(title)).moveDown(0.5);
    doc.fontSize(11).font("Helvetica").text(String(content || ""), { lineGap: 4 });
    doc.end();
    const buf = await done;
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${(filename || "document.pdf").replace(/[/\\"]/g, "_")}"`);
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(buf);
  } catch (e: any) { return res.status(500).json({ error: e?.message }); }
});

export default serverless(app);
