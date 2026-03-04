import type { Express, Request, Response } from "express";
import { storage } from "./storage";
import {
  AnalyzeCvInputSchema,
  GenerateMaterialsInputSchema,
  JobMatchInputSchema,
  JobSearchInputSchema,
  SaveJobApplicationInputSchema,
  PdfInputSchema,
  RegisterInputSchema,
  LoginInputSchema,
} from "../shared/routes";
import { analyzeCvText, aiGenerate, aiMatch, buildSearchQueryFromResume } from "./openai";
import { searchJobsUK } from "./serper";
import { rerankJobsWithJina } from "./jina";
import { createPdfFromText } from "./services/pdf";
import {
  getAuthedUser,
  requireAuth,
  registerWithEmailPassword,
  loginWithEmailPassword,
  signAuthToken,
  setAuthCookie,
  clearAuthCookie,
} from "./auth";

import multer from "multer";
import pdfParse from "pdf-parse";
import mammoth from "mammoth";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

function safeTrim(s: any, fallback = "") {
  const t = String(s ?? "").trim();
  return t || fallback;
}

function isAutoQuery(q: string) {
  const t = safeTrim(q).toLowerCase();
  if (t === "auto" || t === "auto-from-cv" || t === "from-cv") return true;
  if (t === "auto from cv" || t === "auto (from cv)" || t === "auto-from-cv)") return true;
  if (t.includes("auto") && t.includes("cv")) return true;
  return false;
}

export function registerRoutes(app: Express) {
  app.get("/api/healthz", (_req, res) => res.json({ ok: true }));

  // ─── Google OAuth Setup ──────────────────────────────────────────────────
  const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
  const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
  const GOOGLE_CALLBACK_URL =
    process.env.GOOGLE_CALLBACK_URL || "https://jobco.weomeo.win/api/auth/google/callback";

  if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: GOOGLE_CLIENT_ID,
          clientSecret: GOOGLE_CLIENT_SECRET,
          callbackURL: GOOGLE_CALLBACK_URL,
        },
        async (_accessToken, _refreshToken, profile, done) => {
          try {
            const email =
              profile.emails?.[0]?.value?.trim().toLowerCase() ?? null;
            const name =
              profile.displayName ||
              `${profile.name?.givenName ?? ""} ${profile.name?.familyName ?? ""}`.trim() ||
              null;

            if (!email) return done(new Error("No email from Google"), undefined as any);

            let user = await storage.getUserByEmail(email);
            if (!user) {
              user = await storage.createUser({ email, name, passwordHash: null });
            }

            return done(null, { id: user.id, email: user.email, name: user.name ?? null });
          } catch (err: any) {
            return done(err, undefined as any);
          }
        }
      )
    );

    app.use(passport.initialize());

    app.get(
      "/api/auth/google",
      passport.authenticate("google", { scope: ["profile", "email"], session: false })
    );

    app.get(
      "/api/auth/google/callback",
      passport.authenticate("google", { session: false, failureRedirect: "/login?error=google" }),
      (req: any, res: Response) => {
        try {
          const user = req.user as { id: string; email: string; name: string | null };
          const token = signAuthToken(user);
          setAuthCookie(res, token);
          res.redirect("/dashboard");
        } catch {
          res.redirect("/login?error=token");
        }
      }
    );
  } else {
    app.get("/api/auth/google", (_req, res) => {
      res.status(501).json({ error: "Google OAuth is not configured on this server." });
    });
    app.get("/api/auth/google/callback", (_req, res) => {
      res.redirect("/login?error=google_not_configured");
    });
  }

  // ─── Email / Password AUTH ───────────────────────────────────────────────
  app.post("/api/auth/register", async (req: Request, res: Response) => {
    try {
      const parsed = RegisterInputSchema.parse(req.body);
      const user = await registerWithEmailPassword(parsed);
      const token = signAuthToken(user);
      setAuthCookie(res, token);
      return res.json(user);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Register failed" });
    }
  });

  app.post("/api/auth/login", async (req: Request, res: Response) => {
    try {
      const parsed = LoginInputSchema.parse(req.body);
      const user = await loginWithEmailPassword(parsed);
      const token = signAuthToken(user);
      setAuthCookie(res, token);
      return res.json(user);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Login failed" });
    }
  });

  app.post("/api/auth/logout", (_req: any, res: any) => {
    clearAuthCookie(res);
    res.json({ ok: true });
  });

  app.get("/api/auth/me", requireAuth, (req: any, res: any) => {
    res.json(getAuthedUser(req));
  });

  // ─── PROFILE ─────────────────────────────────────────────────────────────
  app.get("/api/profile", requireAuth, async (req: any, res: any) => {
    try {
      const user = getAuthedUser(req);
      const profile = await (storage as any).getUserProfile?.(user.id);
      return res.json(profile ?? null);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Failed to load profile" });
    }
  });

  app.patch("/api/profile", requireAuth, async (req: any, res: any) => {
    try {
      const user = getAuthedUser(req);
      const updates = req.body || {};
      const out = await (storage as any).upsertUserProfile?.(user.id, updates);
      return res.json(out);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Profile update failed" });
    }
  });

  // ─── CV UPLOAD ────────────────────────────────────────────────────────────
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 1 * 1024 * 1024 },
  });

  async function extractTextFromBuffer(file: Express.Multer.File) {
    const name = (file.originalname || "").toLowerCase();
    if (name.endsWith(".pdf")) {
      const out = await pdfParse(file.buffer);
      return (out.text || "").trim();
    }
    if (name.endsWith(".docx")) {
      const out = await mammoth.extractRawText({ buffer: file.buffer });
      return (out.value || "").trim();
    }
    if (name.endsWith(".txt")) {
      return file.buffer.toString("utf8").trim();
    }
    const asText = file.buffer.toString("utf8").trim();
    if (asText.length > 30) return asText;
    throw new Error("Unsupported file type. Please upload .pdf, .docx, or .txt.");
  }

  app.post("/api/profile/upload-cv", requireAuth, async (req: any, res: any) => {
    upload.single("file")(req, res, async (err: any) => {
      try {
        if (err) return res.status(400).json({ error: err?.message || "Upload failed" });
        const file = req.file as Express.Multer.File | undefined;
        if (!file) return res.status(400).json({ error: "No file" });
        const text = await extractTextFromBuffer(file);
        if (!text || text.length < 10) {
          return res
            .status(400)
            .json({ error: "Could not extract text. Try another file or paste manually." });
        }
        const user = getAuthedUser(req);
        const out = await (storage as any).upsertUserProfile?.(user.id, {
          resumeText: text,
          cvFileUrl: null,
        });
        return res.json({ ok: true, filename: file.originalname, text, profile: out ?? null });
      } catch (e: any) {
        return res.status(400).json({ error: e?.message || "Upload failed" });
      }
    });
  });

  app.post("/api/profile/analyze-cv", requireAuth, async (req: any, res: any) => {
    try {
      const body = AnalyzeCvInputSchema.parse(req.body);
      const result = await analyzeCvText({ cvText: body.cvText });
      res.json(result);
    } catch (e: any) {
      res.status(400).json({ error: e?.message || "Analyze failed" });
    }
  });

  // ─── JOBS: SEARCH ────────────────────────────────────────────────────────
  // ─── Fetch full job description via Jina Reader ─────────────────────────
  async function fetchJobDescription(url: string): Promise<string> {
    try {
      const jinaKey = process.env.JINA_API_KEY;
      const headers: any = { "Accept": "text/plain", "X-No-Cache": "true" };
      if (jinaKey) headers["Authorization"] = `Bearer ${jinaKey}`;
      const res = await fetch(`https://r.jina.ai/${url}`, { headers, signal: AbortSignal.timeout(8000) });
      if (!res.ok) return "";
      const text = await res.text();
      // Return first 3000 chars - enough for job description
      return text.slice(0, 3000).trim();
    } catch {
      return "";
    }
  }

  app.post("/api/jobs/search", requireAuth, async (req: Request, res: Response) => {
    try {
      const body = JobSearchInputSchema.parse(req.body);
      const effectiveQuery = await buildSearchQueryFromResume({
        userKeywords: isAutoQuery(body.query) ? "" : body.query,
        resumeText: body.resumeText || "",
      });
      const effectiveLocation = safeTrim(body.location, "Worldwide");
      const found = await searchJobsUK({ query: effectiveQuery, location: effectiveLocation });

      // Take top 10 candidates for reranking/enrichment
      const candidates = found.slice(0, 10);

      // Rerank with Jina if resume provided
      let ranked = candidates;
      if (body.resumeText && safeTrim(body.resumeText).length > 20 && candidates.length > 1) {
        const rerankQuery = `Find the best matching jobs for this profile: ${effectiveQuery}`;
        ranked = await rerankJobsWithJina({ query: rerankQuery, jobs: candidates });
      }

      // Take top 5 and enrich with full job descriptions via Jina Reader
      const top5 = ranked.slice(0, 5);
      const enriched = await Promise.all(
        top5.map(async (job) => {
          const fullDesc = await fetchJobDescription(job.url);
          return {
            ...job,
            description: fullDesc.length > 100 ? fullDesc : job.description,
          };
        })
      );

      return res.json(enriched);
    } catch (e: any) {
      console.error("❌ /api/jobs/search error:", e);
      return res.status(400).json({ error: e?.message || "Search failed" });
    }
  });

  // ─── JOBS: MATCH ─────────────────────────────────────────────────────────
  app.post("/api/jobs/match", requireAuth, async (req: Request, res: Response) => {
    try {
      const body = JobMatchInputSchema.parse(req.body);
      const result = await aiMatch(body.jobDescription);
      res.json(result);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Match failed" });
    }
  });

  // ─── JOBS: GENERATE ──────────────────────────────────────────────────────
  app.post("/api/jobs/generate", requireAuth, async (req: Request, res: Response) => {
    try {
      const body = GenerateMaterialsInputSchema.parse(req.body);
      const result = await aiGenerate({
        jobTitle: body.jobTitle,
        companyName: body.companyName,
        combinedText: body.combinedText,
      });
      res.json(result);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Generate failed" });
    }
  });

  // ─── JOBS: SAVE / LIST ───────────────────────────────────────────────────
  app.post("/api/jobs/save", requireAuth, async (req: any, res: any) => {
    try {
      const user = getAuthedUser(req);
      const body = SaveJobApplicationInputSchema.parse(req.body);
      const out = await (storage as any).saveJobApplication?.(user.id, body);
      return res.status(201).json(out ?? { ok: true });
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Save failed" });
    }
  });

  app.get("/api/jobs/saved", requireAuth, async (req: any, res: any) => {
    try {
      const user = getAuthedUser(req);
      const out = await (storage as any).listSavedJobs?.(user.id);
      return res.json(out ?? []);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Load saved jobs failed" });
    }
  });

  // ─── PDF ─────────────────────────────────────────────────────────────────
  app.post("/api/pdf", requireAuth, async (req: Request, res: Response) => {
    try {
      const body = PdfInputSchema.parse(req.body);
      const buf = await createPdfFromText({
        title: safeTrim((body as any).title, "Document"),
        content: body.content,
      } as any);
      if (
        !Buffer.isBuffer(buf) ||
        buf.length < 10 ||
        buf.subarray(0, 5).toString("utf8") !== "%PDF-"
      ) {
        const preview = Buffer.isBuffer(buf)
          ? buf.toString("utf8").slice(0, 500)
          : String(buf);
        return res
          .status(500)
          .json({ error: "PDF generator returned non-PDF output", preview });
      }
      res.setHeader("Content-Type", "application/pdf");
      const fname = safeTrim((body as any).filename, "document.pdf").replace(/[/\\\"]/g, "_");
      res.setHeader("Content-Disposition", `attachment; filename="${fname}"`);
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Length", String(buf.length));
      return res.status(200).send(buf);
    } catch (e: any) {
      return res.status(500).json({ error: e?.message || "PDF failed" });
    }
  });

  // ─── RESUME UPLOAD ───────────────────────────────────────────────────────
  app.post("/api/resume/upload", requireAuth, async (req: any, res: any) => {
    upload.single("file")(req, res, async (err: any) => {
      try {
        if (err) return res.status(400).json({ error: err?.message || "Upload failed" });
        const file = req.file as Express.Multer.File | undefined;
        if (!file) return res.status(400).json({ error: "No file" });
        const text = await extractTextFromBuffer(file);
        return res.json({ ok: true, filename: file.originalname, text });
      } catch (e: any) {
        return res.status(400).json({ error: e?.message || "Upload failed" });
      }
    });
  });
}
