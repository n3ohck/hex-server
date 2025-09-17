# Hex Data Service Dockerfile

# Development stage
FROM node:20-alpine AS development

WORKDIR /app

# Copy package files
COPY services/hex-data-service/package*.json ./
COPY services/hex-data-service/tsconfig.json ./

# Install all dependencies (including dev dependencies)
RUN npm install

# Copy source code
COPY services/hex-data-service/src/ ./src/
COPY shared/ ./shared/

# Create logs directory
RUN mkdir -p /app/logs

# Expose ports
EXPOSE 3001 9000

# Start in development mode
CMD ["npm", "run", "dev"]

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

# Copy package files
COPY services/hex-data-service/package*.json ./
COPY services/hex-data-service/tsconfig.json ./

# Install dependencies
RUN npm install --only=production

# Copy source code
COPY services/hex-data-service/src/ ./src/
COPY shared/ ./shared/

# Build the application
RUN npm run build

# Create logs directory
RUN mkdir -p /app/logs

# Expose ports
EXPOSE 3001 9000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

# Start the application
CMD ["npm", "start"]
