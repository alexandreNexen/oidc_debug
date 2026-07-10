## Stage 1 — backend dependencies
FROM node:20-alpine AS backend-deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

## Stage 2 — frontend build (Vite)
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/index.html frontend/vite.config.js ./
COPY frontend/src ./src
RUN npm run build

## Stage 3 — runtime image
FROM node:20-alpine AS runtime
WORKDIR /app

# Backend dependencies (production only)
COPY --from=backend-deps /app/node_modules ./node_modules

# Backend sources
COPY package.json ./package.json
COPY src ./src
COPY public ./public
COPY README.md ./README.md

# Vite build (SPA served under /vite/* only)
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

ENV PORT=3000
ENV NODE_ENV=production

EXPOSE 3000

CMD ["npm", "start"]
