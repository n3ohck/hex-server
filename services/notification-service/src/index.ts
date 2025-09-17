import express from 'express';
import cors from 'cors';
import { NotificationService } from './services/notification-service';
import { DeviceService } from './services/device-service';
import { QueueService } from './services/queue-service';
import { initializeFirebase } from './config/firebase';
import { initializeWebPush } from './config/web-push';
import { requestLogger, errorHandler, corsMiddleware } from '../shared/middleware';
import { createNotificationRoutes } from './routes/notifications';
import { createDeviceRoutes } from './routes/devices';
import { createWebPushRoutes } from './routes/web-push';

const app = express();
const PORT = process.env.PORT || 3002;

// Initialize Firebase and Web Push
initializeFirebase();
initializeWebPush();

// Initialize services
const queueService = new QueueService();
const deviceService = new DeviceService();
const notificationService = new NotificationService(queueService);

// Middleware
app.use(corsMiddleware);
app.use(cors());
app.use(express.json());
app.use(requestLogger);

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    success: true, 
    service: 'notification-service',
    status: 'healthy'
  });
});

// Routes
app.use('/api/notifications', createNotificationRoutes(notificationService));
app.use('/api/devices', createDeviceRoutes(deviceService));
app.use('/api/web-push', createWebPushRoutes(notificationService));

// Error handling
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  console.log(`🔔 Notification Service running on port ${PORT}`);
  console.log(`📱 Push notifications ready`);
  console.log(`🌐 Web push ready`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Graceful shutdown initiated');
  await queueService.close();
  process.exit(0);
});