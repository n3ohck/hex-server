# API Gateway Dockerfile

# Development stage
FROM node:20-alpine AS development

WORKDIR /app

# Copy package files
COPY services/api-gateway/package*.json ./
COPY services/api-gateway/tsconfig.json ./

# Install all dependencies (including dev dependencies)
RUN npm install

# Copy source code
COPY services/api-gateway/src/ ./src/
COPY shared/ ./shared/
COPY docs/ ./docs/

# Expose port
EXPOSE 3000

# Start in development mode
CMD ["npm", "run", "dev"]

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

# Copy package files
COPY services/api-gateway/package*.json ./
COPY services/api-gateway/tsconfig.json ./

# Install dependencies
RUN npm install --only=production

# Copy source code
COPY services/api-gateway/src/ ./src/
COPY shared/ ./shared/
COPY docs/ ./docs/

# Build the application
RUN npm run build

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health/gateway', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

# Start the application
CMD ["npm", "start"]
