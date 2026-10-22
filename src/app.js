import { randomBytes, timingSafeEqual } from "node:crypto";
import cors from "cors";
import express from "express";
import { rateLimit } from "express-rate-limit";
import helmet from "helmet";
import passport from "passport";
import { prisma } from "./db.js";
import { configurePassport, issueTokenPair, refreshExpiry, STRATEGIES } from "./auth.js";
import { createRefreshToken, hashRefreshToken, signAccessToken, verifyAccessToken } from "./tokens.js";

const bearerPattern = /^Bearer ([^\s]+)$/i;

function noStore(res) {
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");
}

function cookieValue(req, name) {
  const cookies = req.headers.cookie?.split(";") ?? [];
  const entry = cookies.map((cookie) => cookie.trim()).find((cookie) => cookie.startsWith(`${name}=`));
  return entry ? entry.slice(name.length + 1) : undefined;
}

function validOAuthState(req, provider) {
  const cookieState = cookieValue(req, `oauth_state_${provider}`);
  const queryState = req.query.state;
  if (typeof cookieState !== "string" || typeof queryState !== "string") return false;
  const cookieBuffer = Buffer.from(cookieState);
  const queryBuffer = Buffer.from(queryState);
  return cookieBuffer.length === queryBuffer.length && timingSafeEqual(cookieBuffer, queryBuffer);
}

function createAuthMiddleware(config) {
  return (req, res, next) => {
    const match = bearerPattern.exec(req.get("authorization") ?? "");
    if (!match) {
      return res.status(401).json({ error: "unauthorized", message: "A valid Bearer token is required" });
    }
    try {
      const payload = verifyAccessToken(match[1], config);
      if (typeof payload === "string" || typeof payload.sub !== "string") {
        return res.status(401).json({ error: "unauthorized", message: "Invalid access token" });
      }
      req.auth = { userId: payload.sub };
      return next();
    } catch {
      return res.status(401).json({ error: "unauthorized", message: "Invalid or expired access token" });
    }
  };
}

export function createApp(config) {
  configurePassport(config);
  const app = express();
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "rate_limit_exceeded" },
  });
  const refreshLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "rate_limit_exceeded" },
  });

  app.disable("x-powered-by");
  app.use(helmet());
  app.use(
    cors({
      origin(origin, callback) {
        if (!origin || config.corsOrigins.includes(origin)) return callback(null, true);
        return callback(null, false);
      },
    }),
  );
  app.use(express.json({ limit: "10kb" }));
  app.use(passport.initialize());

  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  app.get("/ready", async (_req, res, next) => {
    try {
      await prisma.$queryRaw`SELECT 1`;
      return res.json({ status: "ready" });
    } catch (error) {
      return next(error);
    }
  });

  app.get("/auth/providers", (_req, res) => {
    return res.json({
      providers: Object.entries(STRATEGIES).map(([name, strategy]) => ({
        name,
        enabled: Boolean(config.providers[name].clientID && config.providers[name].clientSecret),
        authorization_url: `${config.publicUrl}/auth/${name}`,
        callback_url: config.providers[name].callbackURL,
        scope: strategy.scope,
      })),
    });
  });

  app.get("/auth/me", createAuthMiddleware(config), async (req, res, next) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.auth.userId },
        select: { id: true, email: true, name: true, image: true, createdAt: true },
      });
      if (!user) return res.status(401).json({ error: "unauthorized" });
      return res.json({ user });
    } catch (error) {
      return next(error);
    }
  });

  app.get("/auth/:provider", authLimiter, (req, res, next) => {
    const strategy = STRATEGIES[req.params.provider];
    if (!strategy) return res.status(404).json({ error: "unsupported_provider" });
    const credentials = config.providers[req.params.provider];
    if (!credentials.clientID || !credentials.clientSecret) {
      return res.status(503).json({ error: "provider_not_configured" });
    }
    const state = randomBytes(32).toString("base64url");
    res.cookie(`oauth_state_${req.params.provider}`, state, {
      httpOnly: true,
      secure: config.publicUrl.startsWith("https://"),
      sameSite: "lax",
      maxAge: 10 * 60 * 1000,
      path: "/auth",
    });
    return passport.authenticate(req.params.provider, {
      session: false,
      scope: strategy.scope,
      state,
    })(req, res, next);
  });

  app.get("/auth/:provider/callback", authLimiter, (req, res, next) => {
    const strategy = STRATEGIES[req.params.provider];
    if (!strategy) return res.status(404).json({ error: "unsupported_provider" });
    const credentials = config.providers[req.params.provider];
    if (!credentials.clientID || !credentials.clientSecret) {
      return res.status(503).json({ error: "provider_not_configured" });
    }
    res.clearCookie(`oauth_state_${req.params.provider}`, { path: "/auth" });
    if (!validOAuthState(req, req.params.provider)) {
      noStore(res);
      return res.status(401).json({ error: "oauth_state_invalid" });
    }

    return passport.authenticate(req.params.provider, { session: false }, async (error, user) => {
      if (error) return next(error);
      if (!user) {
        noStore(res);
        return res.status(401).json({ error: "oauth_failed" });
      }
      try {
        const tokens = await issueTokenPair(user.id, config);
        noStore(res);
        return res.json({
          ...tokens,
          user: { id: user.id, email: user.email, name: user.name, image: user.image },
        });
      } catch (issueError) {
        return next(issueError);
      }
    })(req, res, next);
  });

  app.post("/auth/refresh", refreshLimiter, async (req, res, next) => {
    const token = req.body?.refreshToken;
    if (typeof token !== "string" || token.length < 32 || token.length > 256) {
      return res.status(400).json({ error: "invalid_request", message: "refreshToken is required" });
    }

    const tokenHash = hashRefreshToken(token);
    try {
      const outcome = await prisma.$transaction(async (tx) => {
        const current = await tx.refreshToken.findUnique({ where: { tokenHash } });
        if (!current) return { valid: false };

        const now = new Date();
        if (current.revokedAt) {
          await tx.refreshToken.updateMany({
            where: { familyId: current.familyId, revokedAt: null },
            data: { revokedAt: now },
          });
          return { valid: false };
        }
        if (current.expiresAt <= now) {
          await tx.refreshToken.updateMany({
            where: { id: current.id, revokedAt: null },
            data: { revokedAt: now },
          });
          return { valid: false };
        }

        const revoked = await tx.refreshToken.updateMany({
          where: { id: current.id, revokedAt: null, expiresAt: { gt: now } },
          data: { revokedAt: now },
        });
        if (revoked.count !== 1) {
          await tx.refreshToken.updateMany({
            where: { familyId: current.familyId, revokedAt: null },
            data: { revokedAt: now },
          });
          return { valid: false };
        }

        const replacementToken = createRefreshToken();
        await tx.refreshToken.create({
          data: {
            tokenHash: replacementToken.tokenHash,
            familyId: current.familyId,
            userId: current.userId,
            expiresAt: refreshExpiry(config),
          },
        });
        return { valid: true, current, replacementRawToken: replacementToken.token };
      });

      if (!outcome.valid) {
        noStore(res);
        return res.status(401).json({ error: "invalid_refresh_token" });
      }

      noStore(res);
      return res.json({
        access_token: signAccessToken(outcome.current.userId, config),
        refresh_token: outcome.replacementRawToken,
        token_type: "Bearer",
        expires_in: config.accessTokenTtlSeconds,
      });
    } catch (error) {
      return next(error);
    }
  });

  app.post("/auth/logout", refreshLimiter, async (req, res, next) => {
    const token = req.body?.refreshToken;
    if (typeof token !== "string" || token.length < 32 || token.length > 256) {
      return res.status(400).json({ error: "invalid_request", message: "refreshToken is required" });
    }
    try {
      const refreshToken = await prisma.refreshToken.findUnique({
        where: { tokenHash: hashRefreshToken(token) },
        select: { familyId: true },
      });
      if (refreshToken) {
        await prisma.refreshToken.updateMany({
          where: { familyId: refreshToken.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
      }
      noStore(res);
      return res.status(204).end();
    } catch (error) {
      return next(error);
    }
  });

  app.use((_req, res) => res.status(404).json({ error: "not_found" }));
  app.use((error, _req, res, _next) => {
    const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 500
      ? error.status
      : 500;
    if (status < 500) {
      return res.status(status).json({ error: "invalid_request" });
    }
    console.error("Request failed:", error);
    if (res.headersSent) return;
    return res.status(500).json({ error: "internal_server_error" });
  });

  return app;
}
