import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";

const config = loadConfig({
  DATABASE_URL: "postgresql://user:password@localhost:5432/oauth",
  JWT_SECRET: "a-secure-test-secret-with-at-least-32-bytes",
});

test("health and provider discovery endpoints are available without provider credentials", async (t) => {
  const server = createApp(config).listen(0);
  await once(server, "listening");
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));

  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const health = await fetch(`${baseUrl}/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ok" });

  const providers = await fetch(`${baseUrl}/auth/providers`);
  assert.equal(providers.status, 200);
  assert.deepEqual(
    (await providers.json()).providers.map(({ name, enabled }) => ({ name, enabled })),
    [{ name: "google", enabled: false }, { name: "github", enabled: false }],
  );

  const unavailableProvider = await fetch(`${baseUrl}/auth/google`, { redirect: "manual" });
  assert.equal(unavailableProvider.status, 503);
  assert.deepEqual(await unavailableProvider.json(), { error: "provider_not_configured" });

  const unauthenticatedProfile = await fetch(`${baseUrl}/auth/me`);
  assert.equal(unauthenticatedProfile.status, 401);
  assert.deepEqual(await unauthenticatedProfile.json(), {
    error: "unauthorized",
    message: "A valid Bearer token is required",
  });

  const malformedJson = await fetch(`${baseUrl}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{",
  });
  assert.equal(malformedJson.status, 400);
  assert.deepEqual(await malformedJson.json(), { error: "invalid_request" });

  const missingRefreshToken = await fetch(`${baseUrl}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  assert.equal(missingRefreshToken.status, 400);

  const missingLogoutToken = await fetch(`${baseUrl}/auth/logout`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  assert.equal(missingLogoutToken.status, 400);

  const unsupportedProvider = await fetch(`${baseUrl}/auth/unsupported`);
  assert.equal(unsupportedProvider.status, 404);
});

test("configured OAuth providers start redirects and reject callbacks without matching state", async (t) => {
  const configuredConfig = loadConfig({
    DATABASE_URL: "postgresql://user:password@localhost:5432/oauth",
    JWT_SECRET: "a-secure-test-secret-with-at-least-32-bytes",
    GOOGLE_CLIENT_ID: "test-google-client-id",
    GOOGLE_CLIENT_SECRET: "test-google-client-secret",
    GITHUB_CLIENT_ID: "test-github-client-id",
    GITHUB_CLIENT_SECRET: "test-github-client-secret",
  });
  const server = createApp(configuredConfig).listen(0);
  await once(server, "listening");
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));

  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  for (const provider of ["google", "github"]) {
    const start = await fetch(`${baseUrl}/auth/${provider}`, { redirect: "manual" });
    assert.equal(start.status, 302);

    const authorizationUrl = new URL(start.headers.get("location"));
    assert.equal(authorizationUrl.searchParams.get("client_id"), `test-${provider}-client-id`);
    const cookieHeader = start.headers.get("set-cookie");
    assert.match(cookieHeader, new RegExp(`oauth_state_${provider}=`));
    assert.match(cookieHeader, /HttpOnly/i);
    assert.match(cookieHeader, /SameSite=Lax/i);

    const callback = await fetch(
      `${baseUrl}/auth/${provider}/callback?state=${encodeURIComponent(authorizationUrl.searchParams.get("state"))}`,
      { redirect: "manual" },
    );
    assert.equal(callback.status, 401);
    assert.deepEqual(await callback.json(), { error: "oauth_state_invalid" });
  }
});
