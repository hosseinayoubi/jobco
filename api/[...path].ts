import serverless from "serverless-http";
import { createApp } from "../server/app";

// createApp is now async (because registerRoutes is async)
const appPromise = createApp();

export default async function handler(req: any, res: any) {
  const app = await appPromise;
  return serverless(app)(req, res);
}
