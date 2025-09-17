import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { requestLogger, errorHandler } from '../shared/middleware';
import { createHealthRoutes } from './routes/health';

const app = express();
const PORT = process.env.PORT || 3000;

// Load OpenAPI specification
const swaggerDocument = YAML.load(path.join(__dirname, '../docs/openapi.yaml'));

// Services configuration
const SERVICES = {
  'hex-data': {
    url: process.env.HEX_DATA_SERVICE_URL || 'http://localhost:3001',
    timeout: 30000
  },
  'notifications': {
    url: process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:3002',
    timeout: 30000
  }
};

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'ws:', 'wss:'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com']
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:19006'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Id', 'X-User-Role']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(limiter);

// Parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);

// API Documentation
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
  explorer: true,
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Hex Microservices API Documentation',
  customfavIcon: '/favicon.ico',
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    filter: true,
    showRequestHeaders: true
  }
}));

// Serve OpenAPI spec as JSON
app.get('/api/openapi.json', (req, res) => {
  res.json(swaggerDocument);
});

// Health check routes
app.use('/api/health', createHealthRoutes(SERVICES));

// Root health check
app.get('/', (req, res) => {
  res.json({
    success: true,
    service: 'hex-microservices-gateway',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    services: Object.keys(SERVICES),
    documentation: '/api/docs',
    openapi: '/api/openapi.json'
  });
});

// Middleware to pass authentication headers from external auth service
const authHeadersMiddleware = (req: any, res: any, next: any) => {
  // This middleware will be used to pass headers from Laravel auth service
  next();
};

// Hex Data Service Proxy  
app.use('/api/logs', authHeadersMiddleware, createProxyMiddleware({
  target: SERVICES['hex-data'].url,
  changeOrigin: true,
  timeout: SERVICES['hex-data'].timeout,
  pathRewrite: {
    '^/api/logs': '/api/logs'
  },
  onError: (err, req, res) => {
    console.error('Hex Data Service proxy error:', err.message);
    res.status(503).json({
      success: false,
      error: 'Hex Data Service unavailable'
    });
  },
  onProxyReq: (proxyReq, req) => {
    // Pass through authentication headers from Laravel
    const userId = req.get('X-User-Id');
    const userRole = req.get('X-User-Role');
    
    if (userId) {
      proxyReq.setHeader('X-User-Id', userId);
    }
    if (userRole) {
      proxyReq.setHeader('X-User-Role', userRole);
    }
  }
}));

// WebSocket proxy for real-time data
app.use('/socket.io', createProxyMiddleware({
  target: SERVICES['hex-data'].url,
  changeOrigin: true,
  ws: true,
  timeout: SERVICES['hex-data'].timeout
}));

// Notification Service Proxy
app.use('/api/notifications', authHeadersMiddleware, createProxyMiddleware({
  target: SERVICES['notifications'].url,
  changeOrigin: true,
  timeout: SERVICES['notifications'].timeout,
  pathRewrite: {
    '^/api/notifications': '/api/notifications'
  },
  onError: (err, req, res) => {
    console.error('Notification Service proxy error:', err.message);
    res.status(503).json({
      success: false,
      error: 'Notification Service unavailable'
    });
  },
  onProxyReq: (proxyReq, req) => {
    // Pass through authentication headers from Laravel
    const userId = req.get('X-User-Id');
    const userRole = req.get('X-User-Role');
    
    if (userId) {
      proxyReq.setHeader('X-User-Id', userId);
    }
    if (userRole) {
      proxyReq.setHeader('X-User-Role', userRole);
    }
  }
}));

// Device Management Proxy
app.use('/api/devices', authHeadersMiddleware, createProxyMiddleware({
  target: SERVICES['notifications'].url,
  changeOrigin: true,
  timeout: SERVICES['notifications'].timeout,
  pathRewrite: {
    '^/api/devices': '/api/devices'
  },
  onError: (err, req, res) => {
    console.error('Device Service proxy error:', err.message);
    res.status(503).json({
      success: false,
      error: 'Device Service unavailable'
    });
  },
  onProxyReq: (proxyReq, req) => {
    // Pass through authentication headers from Laravel
    const userId = req.get('X-User-Id');
    const userRole = req.get('X-User-Role');
    
    if (userId) {
      proxyReq.setHeader('X-User-Id', userId);
    }
    if (userRole) {
      proxyReq.setHeader('X-User-Role', userRole);
    }
  }
}));

// Public notification endpoints (no auth required)
app.use('/api/public/notifications', createProxyMiddleware({
  target: SERVICES['notifications'].url,
  changeOrigin: true,
  timeout: SERVICES['notifications'].timeout,
  pathRewrite: {
    '^/api/public/notifications': '/api'
  },
  onError: (err, req, res) => {
    console.error('Public Notification Service proxy error:', err.message);
    res.status(503).json({
      success: false,
      error: 'Notification Service unavailable'
    });
  }
}));

// Handle 404
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
});

// Error handling
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  console.log(`🚪 API Gateway running on port ${PORT}`);
  console.log(`🔗 Proxying to:`);
  Object.entries(SERVICES).forEach(([name, config]) => {
    console.log(`   ${name}: ${config.url}`);
  });
  console.log(`📚 Documentation: http://localhost:${PORT}/api/docs`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 API Gateway shutting down gracefully');
  process.exit(0);
});