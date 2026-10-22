import { createHash, randomBytes, randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";

export function hashRefreshToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function createRefreshToken() {
  const token = randomBytes(48).toString("base64url");
  return { token, tokenHash: hashRefreshToken(token), familyId: randomUUID() };
}

export function signAccessToken(userId, config) {
  return jwt.sign({}, config.jwtSecret, {
    algorithm: "HS256",
    subject: userId,
    issuer: config.issuer,
    audience: config.audience,
    expiresIn: config.accessTokenTtl,
  });
}

export function verifyAccessToken(token, config) {
  return jwt.verify(token, config.jwtSecret, {
    algorithms: ["HS256"],
    issuer: config.issuer,
    audience: config.audience,
  });
}
