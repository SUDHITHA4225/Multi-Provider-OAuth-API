FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY prisma ./prisma
COPY src ./src
COPY prisma.config.ts ./
RUN npx prisma generate

USER node
EXPOSE 3000

CMD ["sh", "-c", "npx prisma migrate deploy && node src/server.js"]
