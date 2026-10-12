# Standalone synthetic fixture only. Repository-root context, pinned Node22 base digest.
ARG BASE
FROM ${BASE}
WORKDIR /opt/fixture
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
COPY experimental/matrix-client/package.json experimental/matrix-client/package-lock.json ./
RUN npm ci --include=dev && npx --no-install playwright install chromium --with-deps && chmod -R a+rX /opt/playwright
COPY experimental/owned-container-phase-lab/phase-worker.mjs experimental/owned-container-phase-lab/phase-worker-contract.mjs ./
USER 10001:10001
ENTRYPOINT ["node", "/opt/fixture/phase-worker.mjs"]
