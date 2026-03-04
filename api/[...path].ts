import type { VercelRequest, VercelResponse } from "@vercel/node";
import app from "../dist/vercel.cjs";

export default function handler(req: VercelRequest, res: VercelResponse) {
  return (app as any)(req, res);
}
