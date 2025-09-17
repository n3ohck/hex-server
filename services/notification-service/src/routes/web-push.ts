import { Router, Request, Response } from 'express';
import { NotificationService } from '../services/notification-service';
import { generateVapidKeys, isWebPushReady } from '../config/web-push';
import { ApiResponse } from '../../shared/types';

export const createWebPushRoutes = (notificationService: NotificationService): Router => {
  const router = Router();

  // GET /api/web-push/vapid-public-key - Get VAPID public key for client registration
  router.get('/vapid-public-key', (req: Request, res: Response<ApiResponse>) => {
    try {
      const publicKey = process.env.VAPID_PUBLIC_KEY;
      
      if (!publicKey) {
        return res.status(503).json({
          success: false,
          error: 'Web Push not configured - VAPID keys not set'
        });
      }

      res.json({
        success: true,
        data: {
          publicKey,
          isConfigured: isWebPushReady()
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/web-push/generate-keys - Generate new VAPID keys (development only)
  router.post('/generate-keys', (req: Request, res: Response<ApiResponse>) => {
    try {
      if (process.env.NODE_ENV === 'production') {
        return res.status(403).json({
          success: false,
          error: 'Key generation disabled in production'
        });
      }

      const keys = generateVapidKeys();
      
      res.json({
        success: true,
        data: {
          publicKey: keys.publicKey,
          privateKey: keys.privateKey,
          notice: 'Store these keys securely as environment variables'
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/web-push/subscribe - Test web push subscription
  router.post('/subscribe', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { subscription } = req.body;
      
      if (!subscription || !subscription.endpoint || !subscription.keys) {
        return res.status(400).json({
          success: false,
          error: 'Invalid subscription object'
        });
      }

      // Store the subscription (in a real app, you'd save this to database)
      // For now, just validate it by sending a test notification
      
      const testNotification = {
        deviceTokens: [JSON.stringify(subscription)],
        payload: {
          title: '🎉 Web Push Activated!',
          body: 'You will now receive notifications from this app.',
          icon: '/icon-192x192.png',
          data: {
            url: '/',
            subscribed: true
          }
        }
      };

      const result = await notificationService.sendNotification(testNotification);
      
      res.json({
        success: result.success,
        data: {
          subscription,
          testResult: result
        },
        message: result.success ? 'Subscription successful!' : 'Subscription registered but test failed'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/web-push/send - Send web push notification
  router.post('/send', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { subscriptions, title, body, icon, data, url } = req.body;
      
      if (!subscriptions || !Array.isArray(subscriptions) || subscriptions.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'subscriptions must be a non-empty array'
        });
      }

      if (!title || !body) {
        return res.status(400).json({
          success: false,
          error: 'title and body are required'
        });
      }

      const notificationRequest = {
        deviceTokens: subscriptions.map(sub => JSON.stringify(sub)),
        payload: {
          title,
          body,
          icon: icon || '/icon-192x192.png',
          data: {
            ...data,
            url: url || '/'
          }
        }
      };

      const result = await notificationService.sendNotification(notificationRequest);
      
      res.json({
        success: result.success,
        data: result,
        message: `Web push sent to ${result.sentCount}/${subscriptions.length} devices`
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // GET /api/web-push/status - Get web push service status
  router.get('/status', (req: Request, res: Response<ApiResponse>) => {
    try {
      const isReady = isWebPushReady();
      const hasPublicKey = !!process.env.VAPID_PUBLIC_KEY;
      const hasPrivateKey = !!process.env.VAPID_PRIVATE_KEY;
      const hasSubject = !!process.env.VAPID_SUBJECT;

      res.json({
        success: true,
        data: {
          isConfigured: isReady,
          hasPublicKey,
          hasPrivateKey,
          hasSubject,
          environment: process.env.NODE_ENV || 'development'
        }
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