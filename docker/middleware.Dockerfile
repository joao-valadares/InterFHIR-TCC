FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914
WORKDIR /app
ENV HEALTH_ACCESS_API_HOST=0.0.0.0
EXPOSE 3000 4000
COPY package.json package-lock.json ./
RUN npm ci
COPY hardhat.config.ts tsconfig.json ./
COPY middleware ./middleware
COPY scripts ./scripts
COPY contracts ./contracts
RUN node scripts/run-hardhat.cjs compile
CMD ["node", "scripts/run-hardhat.cjs", "run", "scripts/start-institution-gateway.ts"]
