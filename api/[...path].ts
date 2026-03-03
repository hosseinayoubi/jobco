import serverless from "serverless-http";
import { createApp } from "../server/app";

const app = createApp();

export default serverless(app);
