import { createApp } from "./app";

// Local dev only (Vercel does NOT use this entrypoint)
const port = Number(process.env.PORT || 3000);

createApp().then((app) => {
  app.listen(port, "0.0.0.0", () => {
    console.log(`[dev] listening on http://localhost:${port}`);
  });
}).catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
