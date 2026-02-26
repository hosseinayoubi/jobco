# Deploy: Vercel + Neon + Prisma (JWT)

## 1) Create Neon database
- Create a Neon project + database.
- Copy the connection strings:
  - `DATABASE_URL` (use Neon **pooled** connection string for runtime)
  - `DIRECT_URL` (use **non-pooled** / direct connection for migrations)

## 2) Set env vars in Vercel
Required:
- `DATABASE_URL`
- `DIRECT_URL`
- `JWT_SECRET` (random 32+ chars)

Also required by your existing features (already in code):
- `OPENAI_API_KEY`
- `JINA_API_KEY`
- `SERPER_API_KEY`

## 3) Prisma migrate
Run locally once:
```bash
npm i
npx prisma generate
npx prisma migrate dev --name init
```

For production deploys, you can run (CI or manually):
```bash
npx prisma migrate deploy
```

## 4) Vercel settings
- Build command: `npm run build`
- Output directory: `dist/public`

API is served from `api/[...path].ts` and mounted under `/api/*`.

## JWT auth
- Token stored in an **httpOnly cookie** named `gnt_token`.
- Client already uses `credentials: "include"` so it works without extra changes.
