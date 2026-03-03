import serverless from "serverless-http";
import { createApp } from "../server/app";

const app = createApp();
const handler = serverless(app);

export default async function (req: any, res: any) {
  await handler(req, res);
}
