import express from "express";
import cookieParser from "cookie-parser";
import { registerRoutes } from "./routes";

export function createApp() {
  const app = express();

  // ✅ Vercel sits behind a proxy
  app.set("trust proxy", 1);

  app.use(express.json({ limit: "2mb" }));
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  registerRoutes(app);
  return app;
}
