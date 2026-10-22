import { randomUUID } from "node:crypto";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import { prisma } from "./db.js";
import { createRefreshToken, hashRefreshToken, signAccessToken } from "./tokens.js";

const STRATEGIES = {
  google: { Strategy: GoogleStrategy, scope: ["profile", "email"] },
  github: { Strategy: GitHubStrategy, scope: ["user:email"] },
};

function profileFields(profile) {
  return {
    email: profile.emails?.[0]?.value?.trim().toLowerCase() || null,
    name: profile.displayName || null,
    image: profile.photos?.[0]?.value || null,
  };
}

async function findOrCreateUser(provider, profile) {
  const accountId = String(profile.id);
  const fields = profileFields(profile);
  const existing = await prisma.oAuthAccount.findUnique({
    where: {
      provider_providerAccountId: { provider, providerAccountId: accountId },
    },
    include: { user: true },
  });
  if (existing) {
    return prisma.user.update({
      where: { id: existing.userId },
      data: {
        email: fields.email ?? existing.user.email,
        name: fields.name ?? existing.user.name,
        image: fields.image ?? existing.user.image,
      },
    });
  }

  try {
    const userId = randomUUID();
    return await prisma.user.create({
      data: {
        id: userId,
        ...fields,
        accounts: {
          create: { provider, providerAccountId: accountId },
        },
      },
    });
  } catch (error) {
    if (error?.code !== "P2002") throw error;

    const racedAccount = await prisma.oAuthAccount.findUnique({
      where: {
        provider_providerAccountId: { provider, providerAccountId: accountId },
      },
      include: { user: true },
    });
    if (!racedAccount) throw error;
    return prisma.user.update({
      where: { id: racedAccount.userId },
      data: {
        email: fields.email ?? racedAccount.user.email,
        name: fields.name ?? racedAccount.user.name,
        image: fields.image ?? racedAccount.user.image,
      },
    });
  }
}

export function refreshExpiry(config) {
  return new Date(Date.now() + config.refreshTokenTtlDays * 24 * 60 * 60 * 1000);
}

export async function issueTokenPair(userId, config) {
  const refresh = createRefreshToken();
  await prisma.refreshToken.create({
    data: {
      tokenHash: refresh.tokenHash,
      familyId: refresh.familyId,
      userId,
      expiresAt: refreshExpiry(config),
    },
  });
  return {
    access_token: signAccessToken(userId, config),
    refresh_token: refresh.token,
    token_type: "Bearer",
    expires_in: config.accessTokenTtlSeconds,
  };
}

export function configurePassport(config) {
  for (const [provider, { Strategy, scope }] of Object.entries(STRATEGIES)) {
    const credentials = config.providers[provider];
    if (!credentials.clientID || !credentials.clientSecret) continue;

    passport.use(
      provider,
      new Strategy(
        {
          clientID: credentials.clientID,
          clientSecret: credentials.clientSecret,
          callbackURL: credentials.callbackURL,
          passReqToCallback: false,
        },
        (accessToken, refreshToken, profile, done) => {
          findOrCreateUser(provider, profile)
            .then((user) => done(null, user))
            .catch(done);
        },
      ),
    );
  }
  return { strategies: STRATEGIES };
}

export { STRATEGIES, findOrCreateUser, hashRefreshToken };
