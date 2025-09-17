# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A modern microservices architecture that evolved from a simple Node.js TCP server into a scalable system with push notifications for web and React Native applications. The system maintains backward compatibility with the original TCP functionality while adding REST APIs, real-time WebSockets, and comprehensive notification services.

## Architecture

The project follows a microservices pattern with three main services:

### Services Structure
```
hex-microservices/
├── services/
│   ├── api-gateway/          # Main entry point (port 3000)
│   ├── hex-data-service/     # TCP + REST APIs (port 3001 + TCP 9000)
│   └── notification-service/ # Push notifications (port 3002)
├── shared/                   # Common types and utilities
│   ├── types/               # TypeScript interfaces
│   ├── middleware/          # Express middleware
│   └── utils/               # Helper functions
└── examples/                # Integration examples
```

### Core Services

1. **API Gateway** (port 3000)
   - Authentication (JWT)
   - Rate limiting
   - Service proxy and routing
   - Health monitoring

2. **Hex Data Service** (port 3001 + TCP 9000)
   - Original TCP server functionality (backward compatible)
   - REST APIs for log querying
   - WebSocket real-time data streaming
   - Log file management

3. **Notification Service** (port 3002)
   - Firebase FCM (mobile push)
   - Web Push API (browser notifications)
   - Redis-based queue system
   - Device token management

## Development Commands

### Main Commands (from root)
```bash
npm install                    # Install all dependencies
npm run dev:all               # Run all services in development
npm run dev:gateway           # Run only API Gateway
npm run dev:hex               # Run only Hex Data Service
npm run dev:notifications     # Run only Notification Service
npm run build                 # Build all services
npm run lint                  # Lint all services
```

### Docker Commands
```bash
docker-compose up -d                                              # Production mode
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up # Development mode
docker-compose logs -f [service_name]                             # View logs
docker-compose down                                                # Stop services
```

### Testing TCP Functionality
```bash
# Original TCP server still works on port 9000
echo "test data" | nc localhost 9000
telnet localhost 9000

# Or use the provided test script
node examples/test-tcp-client.js
```

## Configuration

### Environment Variables
Key environment variables (see .env.example):

- `JWT_SECRET` - JWT signing key
- `FIREBASE_SERVICE_ACCOUNT_KEY` - Firebase credentials for mobile push
- `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` - Web push credentials
- `REDIS_HOST` / `REDIS_PORT` - Redis configuration
- `LOG_DIR` - Log file directory (default: `/var/www/html/hex-server`)

### Service URLs
- API Gateway: http://localhost:3000
- Hex Data Service: http://localhost:3001 (REST) + port 9000 (TCP)
- Notification Service: http://localhost:3002
- Redis Commander: http://localhost:8081 (development)

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/verify` - Token verification

### Hex Data
- `GET /api/hex/logs` - Get logs with pagination/filtering
- `GET /api/hex/logs/client/:ip` - Logs for specific client
- `GET /api/hex/logs/stats` - Logging statistics
- `WS /socket.io` - Real-time WebSocket connection

### Notifications
- `POST /api/notifications/devices/register` - Register device token
- `POST /api/notifications/notifications/send` - Send notification
- `POST /api/notifications/notifications/test` - Send test notification

### Health Checks
- `GET /api/health` - Overall system health
- `GET /api/health/services` - Individual service status
- `GET /api/health/gateway` - Gateway-specific metrics

## Technology Stack

- **Backend**: Node.js, Express.js, TypeScript
- **Authentication**: JWT tokens
- **Real-time**: Socket.io WebSockets
- **Queue**: Redis + Bull
- **Push Notifications**: Firebase FCM, Web Push API
- **Containerization**: Docker, Docker Compose
- **Development**: tsx (TypeScript execution)

## File Organization

### Shared Code
- `shared/types/index.ts` - Common TypeScript interfaces
- `shared/middleware/index.ts` - Express middleware (auth, CORS, logging)
- `shared/utils/index.ts` - Utility functions (ID generation, file handling)

### Service-Specific Structure
Each service follows this pattern:
```
service-name/
├── src/
│   ├── index.ts              # Main entry point
│   ├── routes/               # API route handlers
│   ├── services/             # Business logic
│   └── middleware/           # Service-specific middleware
├── package.json
├── tsconfig.json
└── Dockerfile
```

## Testing & Development

### Authentication
Default users for testing:
- Username: `admin`, Password: `admin123` (role: admin)
- Username: `user`, Password: `user123` (role: user)

### Real-time Testing
Connect to WebSocket at `ws://localhost:3000/socket.io` to receive real-time TCP data events.

### Notification Testing
Use the test endpoints to verify push notification setup:
- Mobile: `POST /api/notifications/notifications/test`
- Web: `POST /api/notifications/web-push/generate-keys` (development)

## Backward Compatibility

The original `server.js` TCP functionality is fully preserved:
- TCP server still runs on port 9000
- Log format remains unchanged: `{timestamp} {clientIP} len={length} HEX={hex} ASCII={ascii}`
- Log files still created in same directory structure
- All existing TCP clients continue to work without modification

## Integration Examples

See `examples/client-examples.md` for detailed integration examples for:
- React Native (FCM setup, real-time data)
- Web applications (Service Workers, WebSocket)
- TCP clients (Node.js and bash examples)
- Authentication workflows

## Deployment Notes

- Use Docker Compose for consistent deployments
- Configure environment variables properly for production
- Set up external Redis for production scale
- Configure Firebase and Web Push credentials
- Use proper JWT secrets and HTTPS in production