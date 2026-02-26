import { createApp } from "./app";

const app = createApp();

// Local dev only (Vercel does NOT use this entrypoint)
const port = Number(process.env.PORT || 3000);
app.listen(port, "0.0.0.0", () => {
  console.log(`[dev] listening on http://localhost:${port}`);
});
