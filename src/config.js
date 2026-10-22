const DEFAULTS = {
  accessTokenTtl: "15m",
  refreshTokenTtlDays: 30,
  port: 3000,
  issuer: "multi-provider-oauth",
  audience: "multi-provider-oauth-api",
};

export function loadConfig(env = process.env) {
  const jwtSecret = env.JWT_SECRET;
  if (!jwtSecret || Buffer.byteLength(jwtSecret) < 32) {
    throw new Error("JWT_SECRET must contain at least 32 bytes");
  }
  if (!env.DATABASE_URL) {
    throw new Error("DATABASE_URL is required");
  }

  const providers = {
    google: {
      clientID: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      callbackURL: env.GOOGLE_CALLBACK_URL ?? "http://localhost:3000/auth/google/callback",
    },
    github: {
      clientID: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
      callbackURL: env.GITHUB_CALLBACK_URL ?? "http://localhost:3000/auth/github/callback",
    },
  };

  for (const [name, provider] of Object.entries(providers)) {
    if (Boolean(provider.clientID) !== Boolean(provider.clientSecret)) {
      throw new Error(`${name.toUpperCase()}_CLIENT_ID and ${name.toUpperCase()}_CLIENT_SECRET must both be set`);
    }
  }

  const refreshTokenTtlDays = Number(env.REFRESH_TOKEN_TTL_DAYS ?? DEFAULTS.refreshTokenTtlDays);
  if (!Number.isInteger(refreshTokenTtlDays) || refreshTokenTtlDays < 1 || refreshTokenTtlDays > 365) {
    throw new Error("REFRESH_TOKEN_TTL_DAYS must be an integer from 1 to 365");
  }

  const port = Number(env.PORT ?? DEFAULTS.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT must be a valid TCP port");
  }
  const accessTokenTtl = env.ACCESS_TOKEN_TTL ?? DEFAULTS.accessTokenTtl;
  const ttlMatch = /^([1-9]\d*)(s|m|h|d)$/.exec(accessTokenTtl);
  if (!ttlMatch) {
    throw new Error("ACCESS_TOKEN_TTL must be a positive duration such as 15m or 1h");
  }
  const accessTokenTtlSeconds =
    Number(ttlMatch[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[ttlMatch[2]];
  if (!Number.isSafeInteger(accessTokenTtlSeconds) || accessTokenTtlSeconds > 86400) {
    throw new Error("ACCESS_TOKEN_TTL must not exceed 1d");
  }

  const issuer = env.JWT_ISSUER ?? DEFAULTS.issuer;
  const audience = env.JWT_AUDIENCE ?? DEFAULTS.audience;
  if (!issuer || !audience) {
    throw new Error("JWT_ISSUER and JWT_AUDIENCE must not be empty");
  }
  const publicUrl = env.PUBLIC_URL ?? "http://localhost:3000";
  let parsedPublicUrl;
  try {
    parsedPublicUrl = new URL(publicUrl);
  } catch {
    throw new Error("PUBLIC_URL must be an absolute HTTP or HTTPS URL");
  }
  if (parsedPublicUrl.protocol !== "http:" && parsedPublicUrl.protocol !== "https:") {
    throw new Error("PUBLIC_URL must be an absolute HTTP or HTTPS URL");
  }

  return {
    jwtSecret,
    issuer,
    audience,
    accessTokenTtl,
    accessTokenTtlSeconds,
    refreshTokenTtlDays,
    port,
    publicUrl: parsedPublicUrl.origin,
    corsOrigins: (env.CORS_ORIGINS ?? "http://localhost:3000")
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean),
    providers,
  };
}
