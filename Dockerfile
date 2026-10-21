# Node 22 on Alpine, API server only (the web UI arrives in a later step). The image can be built later with OrbStack:
#   HOST_PORT=6500 docker compose up --build -d   ->  http://127.0.0.1:6500/api/health
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production AI_GUARD_PORT=6500
COPY package.json package-lock.json ./
COPY server/package.json server/
RUN npm ci --omit=dev -w server --ignore-scripts && npm cache clean --force
COPY server/src server/src
USER node
EXPOSE 6500
# Inside the container the main server must listen on all interfaces, so AI_GUARD_BIND is set here on purpose.
# The embedded stand-in sidecar still binds 127.0.0.1 inside the container; it is never published.
# The compose file publishes 6500 on 127.0.0.1 only; do not publish it more widely.
ENV AI_GUARD_BIND=0.0.0.0
CMD ["node", "server/src/index.js"]
