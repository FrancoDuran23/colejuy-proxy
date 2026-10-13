FROM node:22-alpine
WORKDIR /app
COPY server.mjs .
ENV PORT=8080 NODE_ENV=production
EXPOSE 8080
USER node
CMD ["node", "server.mjs"]
