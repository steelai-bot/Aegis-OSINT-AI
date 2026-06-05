FROM node:24-alpine AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:24-alpine AS builder

WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

ARG NEXT_PUBLIC_AEGIS_API_URL=http://localhost:8000
ARG NEXT_PUBLIC_AEGIS_WS_URL=ws://localhost:8000/api/v1/events
ENV NEXT_PUBLIC_AEGIS_API_URL=$NEXT_PUBLIC_AEGIS_API_URL
ENV NEXT_PUBLIC_AEGIS_WS_URL=$NEXT_PUBLIC_AEGIS_WS_URL

COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN mkdir -p public && npm run build

FROM node:24-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

RUN addgroup -S nextjs && adduser -S nextjs -G nextjs

COPY --from=builder --chown=nextjs:nextjs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nextjs /app/public ./public

USER nextjs
EXPOSE 3000

CMD ["node", "server.js"]
