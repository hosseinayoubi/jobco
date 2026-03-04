import serverless from "serverless-http";
import express from "express";
import cookieParser from "cookie-parser";
import { registerRoutes } from "../server/routes";

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
registerRoutes(app);

export default serverless(app);
