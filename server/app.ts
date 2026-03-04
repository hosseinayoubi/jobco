import { createApp } from "../server/app";
import type { VercelRequest, VercelResponse } from "@vercel/node";

let appPromise: ReturnType<typeof createApp> | null = null;

function getApp() {
  if (!appPromise) {
    appPromise = createApp();
  }
  return appPromise;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const app = await getApp();
  return app(req as any, res as any);
}
