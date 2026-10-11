# Repository-root build context. Parent resolves BASE to Node 22 bookworm-slim RepoDigest.
ARG BASE
FROM ${BASE}
WORKDIR /opt/fixture
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
COPY experimental/matrix-client/package.json experimental/matrix-client/package-lock.json ./
RUN npm ci --include=dev && npx --no-install playwright install chromium --with-deps && chmod -R a+rX /opt/playwright
COPY experimental/owned-container-lab/container-worker.mjs ./container-worker.mjs
USER 10001:10001
ENTRYPOINT ["node", "/opt/fixture/container-worker.mjs"]
