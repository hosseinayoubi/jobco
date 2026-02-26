import serverless from "serverless-http";
import { createApp } from "../server/app";

// ✅ Single Express app instance reused between invocations (best effort)
const app = createApp();

export default serverless(app);
