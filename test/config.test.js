import test from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";

const requiredEnvironment = {
  DATABASE_URL: "postgresql://user:password@localhost:5432/oauth",
  JWT_SECRET: "a-secure-test-secret-with-at-least-32-bytes",
};

test("loads safe defaults and disabled provider settings", () => {
  const config = loadConfig(requiredEnvironment);
  assert.equal(config.port, 3000);
  assert.equal(config.accessTokenTtlSeconds, 900);
  assert.equal(config.providers.google.clientID, undefined);
  assert.deepEqual(config.corsOrigins, ["http://localhost:3000"]);
});

test("rejects missing or weak JWT secrets", () => {
  assert.throws(() => loadConfig({ DATABASE_URL: requiredEnvironment.DATABASE_URL }), /JWT_SECRET/);
  assert.throws(
    () => loadConfig({ ...requiredEnvironment, JWT_SECRET: "too-short" }),
    /at least 32 bytes/,
  );
});

test("requires OAuth client ID and secret as a pair", () => {
  assert.throws(
    () => loadConfig({ ...requiredEnvironment, GOOGLE_CLIENT_ID: "client-id" }),
    /must both be set/,
  );
});

test("rejects invalid token lifetime and port values", () => {
  assert.throws(
    () => loadConfig({ ...requiredEnvironment, ACCESS_TOKEN_TTL: "0m" }),
    /ACCESS_TOKEN_TTL/,
  );
  assert.throws(
    () => loadConfig({ ...requiredEnvironment, ACCESS_TOKEN_TTL: "2d" }),
    /must not exceed 1d/,
  );
  assert.throws(() => loadConfig({ ...requiredEnvironment, PORT: "70000" }), /PORT/);
});
