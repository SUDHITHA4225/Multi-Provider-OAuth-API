import "dotenv/config";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { prisma } from "./db.js";

const config = loadConfig();
const app = createApp(config);
const server = app.listen(config.port, () => {
  console.info(`OAuth API listening on port ${config.port}`);
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.info(`Received ${signal}; shutting down`);
  server.close(async (error) => {
    if (error) {
      console.error("HTTP server shutdown failed:", error);
      process.exitCode = 1;
    }
    try {
      await prisma.$disconnect();
    } catch (disconnectError) {
      console.error("Database shutdown failed:", disconnectError);
      process.exitCode = 1;
    }
  });
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
