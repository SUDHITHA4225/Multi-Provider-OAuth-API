import test from "node:test";
import assert from "node:assert/strict";
import { createRefreshToken, hashRefreshToken, signAccessToken, verifyAccessToken } from "../src/tokens.js";

const config = {
  jwtSecret: "a-secure-test-secret-with-at-least-32-bytes",
  issuer: "test-issuer",
  audience: "test-audience",
  accessTokenTtl: "1h",
};

test("refresh tokens are random, opaque, and persist as one-way hashes", () => {
  const first = createRefreshToken();
  const second = createRefreshToken();
  assert.notEqual(first.token, second.token);
  assert.equal(first.tokenHash, hashRefreshToken(first.token));
  assert.notEqual(first.tokenHash, first.token);
  assert.notEqual(first.familyId, second.familyId);
});

test("access tokens verify only for the configured issuer and audience", () => {
  const token = signAccessToken("user-123", config);
  const payload = verifyAccessToken(token, config);
  assert.equal(payload.sub, "user-123");
  assert.throws(() => verifyAccessToken(token, { ...config, audience: "other-api" }));
});
