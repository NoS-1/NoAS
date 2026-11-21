# 自建 DoH 服务镜像（零外部依赖，只用仓库产物）
FROM node:24-alpine
WORKDIR /app
COPY serve/standalone.mjs doh/worker.js ./
ENV PORT=8053
EXPOSE 8053
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8053/health >/dev/null || exit 1
CMD ["node", "standalone.mjs"]
