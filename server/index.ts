import { createApp } from "./app";

// Local dev only (Vercel does NOT use this entrypoint)
const port = Number(process.env.PORT || 3000);

const app = createApp();

app.listen(port, "0.0.0.0", () => {
  console.log(`[dev] listening on http://localhost:${port}`);
});
