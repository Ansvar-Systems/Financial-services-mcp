FROM node:24-alpine
# Upgrade zlib to >= 1.3.2-r0 to remediate CVE-2026-27171 (CWE-1284)
RUN apk upgrade --no-cache zlib
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
COPY src/ ./src/
COPY data/ ./data/
COPY scripts/ ./scripts/
RUN chown -R nodejs:nodejs /app
USER nodejs
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + process.env.PORT + '/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
CMD ["node", "--experimental-sqlite", "src/index.js"]
