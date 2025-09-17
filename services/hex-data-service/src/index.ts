import express from 'express';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import cors from 'cors';
import { TCPServer } from './tcp-server';
import { LogService } from './log-service';
import { requestLogger, errorHandler, corsMiddleware } from '../shared/middleware';
import { createLogRoutes } from './routes/logs';
import { createRealtimeRoutes } from './routes/realtime';

const app = express();
const httpServer = createServer(app);
const io = new SocketServer(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3001;
const TCP_PORT = process.env.TCP_PORT || 9000;
const LOG_DIR = process.env.LOG_DIR || '/var/www/html/hex-server';

// Initialize services
const logService = new LogService(LOG_DIR);
const tcpServer = new TCPServer(Number(TCP_PORT), logService, io);

// Middleware
app.use(corsMiddleware);
app.use(cors());
app.use(express.json());
app.use(requestLogger);

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    success: true, 
    service: 'hex-data-service',
    status: 'healthy',
    tcpPort: TCP_PORT,
    logDir: LOG_DIR
  });
});

// Routes
app.use('/api/logs', createLogRoutes(logService));
app.use('/api/realtime', createRealtimeRoutes(io));

// Error handling
app.use(errorHandler);

// Start servers
httpServer.listen(PORT, () => {
  console.log(`🚀 Hex Data Service running on port ${PORT}`);
  console.log(`📊 REST API: http://localhost:${PORT}`);
  console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
});

tcpServer.start();

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Graceful shutdown initiated');
  tcpServer.stop();
  httpServer.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});