import { Router, Request, Response } from 'express';
import { NotificationService } from '../services/notification-service';
import { ApiResponse, NotificationRequest } from '../../shared/types';
import { validateRequired } from '../../shared/middleware';

export const createNotificationRoutes = (notificationService: NotificationService): Router => {
  const router = Router();

  // POST /api/notifications/send - Send notification to multiple devices
  router.post('/send', 
    validateRequired(['deviceTokens', 'payload']),
    async (req: Request, res: Response<ApiResponse>) => {
      try {
        const request: NotificationRequest = req.body;
        
        if (!Array.isArray(request.deviceTokens) || request.deviceTokens.length === 0) {
          return res.status(400).json({
            success: false,
            error: 'deviceTokens must be a non-empty array'
          });
        }

        if (!request.payload.title || !request.payload.body) {
          return res.status(400).json({
            success: false,
            error: 'payload must include title and body'
          });
        }

        const result = await notificationService.sendNotification(request);
        
        res.json({
          success: result.success,
          data: result,
          message: `Sent ${result.sentCount}/${request.deviceTokens.length} notifications`
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
  );

  // POST /api/notifications/send-bulk - Send multiple different notifications
  router.post('/send-bulk', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { notifications } = req.body;
      
      if (!Array.isArray(notifications) || notifications.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'notifications must be a non-empty array'
        });
      }

      // Validate each notification
      for (const [index, notification] of notifications.entries()) {
        if (!notification.deviceTokens || !Array.isArray(notification.deviceTokens)) {
          return res.status(400).json({
            success: false,
            error: `Notification ${index}: deviceTokens must be an array`
          });
        }
        if (!notification.payload?.title || !notification.payload?.body) {
          return res.status(400).json({
            success: false,
            error: `Notification ${index}: payload must include title and body`
          });
        }
      }

      const results = await notificationService.sendBulkNotifications(notifications);
      
      const totalSent = results.reduce((sum, result) => sum + result.sentCount, 0);
      const totalAttempted = results.reduce((sum, result) => sum + (result.sentCount + result.failedCount), 0);
      
      res.json({
        success: totalSent > 0,
        data: {
          results,
          summary: {
            totalSent,
            totalAttempted,
            batchCount: notifications.length
          }
        },
        message: `Processed ${notifications.length} notification batches`
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/notifications/broadcast - Send notification to all active devices
  router.post('/broadcast', 
    validateRequired(['payload']),
    async (req: Request, res: Response<ApiResponse>) => {
      try {
        const { payload, platform } = req.body;
        
        // This would require integration with device service
        // For now, return a placeholder response
        res.json({
          success: true,
          message: 'Broadcast feature requires device service integration',
          data: {
            payload,
            platform: platform || 'all',
            note: 'Use /api/notifications/send with device tokens for now'
          }
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
  );

  // GET /api/notifications/queue/stats - Get notification queue statistics
  router.get('/queue/stats', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const stats = await notificationService.getQueueStats();
      
      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/notifications/queue/retry - Retry failed notifications
  router.post('/queue/retry', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const retriedCount = await notificationService.retryFailedNotifications();
      
      res.json({
        success: true,
        data: { retriedCount },
        message: `Retried ${retriedCount} failed notifications`
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/notifications/test - Send test notification
  router.post('/test', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { deviceToken, platform = 'unknown' } = req.body;
      
      if (!deviceToken) {
        return res.status(400).json({
          success: false,
          error: 'deviceToken is required'
        });
      }

      const testRequest: NotificationRequest = {
        deviceTokens: [deviceToken],
        payload: {
          title: '🧪 Test Notification',
          body: `Test from Hex Microservices at ${new Date().toLocaleTimeString()}`,
          data: {
            test: true,
            timestamp: new Date().toISOString(),
            platform
          }
        },
        priority: 'normal'
      };

      const result = await notificationService.sendNotification(testRequest);
      
      res.json({
        success: result.success,
        data: result,
        message: result.success ? 'Test notification sent!' : 'Test notification failed'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  return router;
};