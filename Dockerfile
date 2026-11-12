# Stage 1 builds web/dist; stage 2 is the runtime: API server + the built UI. Build and run with OrbStack (not Docker Desktop):
#   HOST_PORT=6500 docker compose up --build -d   ->  http://127.0.0.1:6500/
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY web/package.json web/
COPY server/package.json server/
RUN npm ci --ignore-scripts
COPY web web
COPY docs docs
RUN npm run build -w web

FROM node:22-alpine
WORKDIR /app
# MODE=local is the standalone demo; the mock-only SE build sets MODE=se-mock in its manifest (k8s/deployment.yaml).
ENV NODE_ENV=production AI_GUARD_PORT=6500 MODE=local
COPY package.json package-lock.json ./
COPY web/package.json web/
COPY server/package.json server/
RUN npm ci --omit=dev -w server --ignore-scripts && npm cache clean --force
COPY server/src server/src
COPY --from=build /app/web/dist web/dist
USER node
EXPOSE 6500
# Inside the container the main server must listen on all interfaces, so AI_GUARD_BIND is set here on purpose.
# The embedded stand-in sidecar still binds 127.0.0.1 inside the container; it is never published.
# The compose file publishes 6500 on 127.0.0.1 only; do not publish it more widely.
ENV AI_GUARD_BIND=0.0.0.0
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:6500/api/health').then(r=>r.json()).then(j=>process.exit(j.state==='ready'?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/src/index.js"]
