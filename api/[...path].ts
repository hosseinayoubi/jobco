import type { VercelRequest, VercelResponse } from "@vercel/node";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const mod = require("../dist/vercel.cjs");
const app = mod.default ?? mod;

export default function handler(req: VercelRequest, res: VercelResponse) {
  return app(req, res);
}
