# Multi-Provider OAuth API

## Overview

The Multi-Provider OAuth API is a secure authentication system that allows users to sign in using their Google or GitHub accounts. It is built using Node.js, Express.js, Passport.js, PostgreSQL, and Prisma.

The API uses JWT access tokens and rotating refresh tokens to manage user sessions. It also includes security features such as OAuth state validation, rate limiting, and protected endpoints to keep user information safe.

## Features

- Google and GitHub OAuth 2.0 login.
- Secure authentication using JWT access tokens.
- Refresh token rotation and revocation.
- User and refresh token storage using PostgreSQL and Prisma.
- Protected API endpoints for authenticated users.
- Health and readiness checks.
- Security headers and request rate limiting.
- Docker and Docker Compose support for easy setup.

## Technologies Used

- **Backend:** Node.js, Express.js
- **Authentication:** OAuth 2.0, Passport.js, JWT
- **Database:** PostgreSQL, Prisma ORM
- **Security:** Helmet, OAuth state validation, rate limiting
- **Containerization:** Docker, Docker Compose

## Project Setup

### Requirements

Make sure you have the following installed:

- Docker Desktop with Docker Compose
- Google and/or GitHub OAuth credentials
- Node.js 20.19+ and npm (only for local development and testing)

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd <your-project-folder>
```

### 2. Configure Environment Variables

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

Open the `.env` file and configure the required values, including:

- PostgreSQL username, password, and database name
- Database connection URL
- A strong JWT secret of at least 32 bytes
- Google and GitHub client IDs and secrets, depending on which providers you want to use

Keep the database credentials synchronized with `DATABASE_URL`. Never upload your `.env` file or real secrets to GitHub.

### 3. Configure OAuth Providers

Create OAuth applications in the Google and GitHub developer consoles and add the corresponding credentials to `.env`.

Use these callback URLs for local development:

- **Google:** `http://localhost:3000/auth/google/callback`
- **GitHub:** `http://localhost:3000/auth/github/callback`

The callback URLs configured with each provider must match the URLs used by the application.

### 4. Start the Application

Run the following command:

```powershell
docker compose up --build
```

Docker Compose starts the PostgreSQL database, applies the Prisma migrations, and starts the API.

After startup, check the following endpoints:

- Health check: `http://localhost:3000/health`
- Readiness check: `http://localhost:3000/ready`

To stop the application, run:

```powershell
docker compose down
```

To stop the application and remove its stored database volume, run:

```powershell
docker compose down -v
```

**Note:** The second command deletes the local database volume and its stored data.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Checks whether the API is running |
| GET | `/ready` | Checks database connectivity |
| GET | `/auth/providers` | Lists supported OAuth providers |
| GET | `/auth/google` | Starts Google sign-in |
| GET | `/auth/github` | Starts GitHub sign-in |
| GET | `/auth/:provider/callback` | Handles the OAuth callback |
| POST | `/auth/refresh` | Rotates a refresh token |
| POST | `/auth/logout` | Revokes a refresh token |
| GET | `/auth/me` | Returns the authenticated user's profile |

### Refresh Token Example

**Request:** `POST /auth/refresh`

```json
{
  "refreshToken": "your-refresh-token"
}
```

The API validates the refresh token, revokes the old token, and returns a new token from the same token family. Reusing a revoked token causes the remaining tokens in that family to be revoked.

## Local Development and Testing

If you want to run tests outside Docker, install the dependencies and generate the Prisma client:

```bash
npm ci
npm run db:generate
npm test
```

Make sure PostgreSQL is running and the required environment variables are configured before starting the application locally.

To apply database migrations, run:

```bash
npm run db:deploy
```

## Security

The API includes several security measures:

- Short-lived JWT access tokens.
- Opaque refresh tokens stored as SHA-256 hashes.
- Refresh token rotation and reuse detection.
- HTTP-only cookies and OAuth state validation during sign-in.
- Security headers using Helmet.
- Request body size limits and rate limiting.
- Environment variables for sensitive configuration.

For production deployment, use HTTPS, strong secrets, secure environment configuration, and the correct public callback URLs.

## Conclusion

The Multi-Provider OAuth API provides a simple and secure way to manage user authentication through Google and GitHub. It combines OAuth 2.0, JWT access tokens, refresh token rotation, and PostgreSQL storage to manage user sessions effectively. Docker makes the application easier to set up and run, while the built-in security features help protect authentication endpoints and user data. This project demonstrates practical backend development skills in authentication, API design, database management, and containerization.