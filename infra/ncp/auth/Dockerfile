# Pinned, digest-locked base image. Do not float this tag.
FROM node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

# Non-root service account
RUN addgroup -S authapp && adduser -S authapp -G authapp -h /app

WORKDIR /app

# Install pinned production dependencies from lockfile.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src

# Data directory for the JSON file store (public device keys + hashed invites).
RUN mkdir -p /data \
    && chown -R authapp:authapp /app /data \
    && chmod 700 /data

USER authapp

ENV NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
