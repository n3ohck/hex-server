import { getFirebaseMessaging } from '../config/firebase';
import { getWebPush, isWebPushReady } from '../config/web-push';
import { QueueService } from './queue-service';
import { NotificationRequest, NotificationPayload } from '../../shared/types';

export interface NotificationResult {
  success: boolean;
  sentCount: number;
  failedCount: number;
  results: Array<{
    token: string;
    success: boolean;
    error?: string;
    messageId?: string;
  }>;
}

export class NotificationService {
  private queueService: QueueService;

  constructor(queueService: QueueService) {
    this.queueService = queueService;
    this.initializeServices();
  }

  private initializeServices(): void {
    // Initialize Firebase
    try {
      getFirebaseMessaging();
    } catch (error) {
      console.warn('Firebase messaging not available');
    }

    // Initialize Web Push
    if (isWebPushReady()) {
      console.log('🌐 Web Push service ready');
    }
  }

  async sendNotification(request: NotificationRequest): Promise<NotificationResult> {
    try {
      // Add to queue for processing
      const job = await this.queueService.addNotificationJob(request);
      
      // For immediate processing, we'll also send directly
      return await this.processSendNotification(request);
    } catch (error) {
      console.error('❌ Error sending notification:', error);
      return {
        success: false,
        sentCount: 0,
        failedCount: request.deviceTokens.length,
        results: request.deviceTokens.map(token => ({
          token,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        }))
      };
    }
  }

  async sendBulkNotifications(requests: NotificationRequest[]): Promise<NotificationResult[]> {
    try {
      // Add all to queue
      await this.queueService.addBulkNotificationJobs(requests);
      
      // Process immediately for demo purposes
      const results = await Promise.all(
        requests.map(request => this.processSendNotification(request))
      );
      
      return results;
    } catch (error) {
      console.error('❌ Error sending bulk notifications:', error);
      throw error;
    }
  }

  private async processSendNotification(request: NotificationRequest): Promise<NotificationResult> {
    const { deviceTokens, payload, priority = 'normal' } = request;
    const results: NotificationResult['results'] = [];
    let sentCount = 0;
    let failedCount = 0;

    // Group tokens by platform (assuming token format indicates platform)
    const mobileTokens = deviceTokens.filter(token => this.isMobileToken(token));
    const webTokens = deviceTokens.filter(token => this.isWebToken(token));

    // Send to mobile devices (FCM)
    if (mobileTokens.length > 0) {
      const mobileResults = await this.sendFirebaseNotifications(mobileTokens, payload, priority);
      results.push(...mobileResults.results);
      sentCount += mobileResults.sentCount;
      failedCount += mobileResults.failedCount;
    }

    // Send to web browsers (Web Push)
    if (webTokens.length > 0) {
      const webResults = await this.sendWebPushNotifications(webTokens, payload);
      results.push(...webResults.results);
      sentCount += webResults.sentCount;
      failedCount += webResults.failedCount;
    }

    return {
      success: sentCount > 0,
      sentCount,
      failedCount,
      results
    };
  }

  private async sendFirebaseNotifications(
    tokens: string[], 
    payload: NotificationPayload, 
    priority: string
  ): Promise<NotificationResult> {
    try {
      const messaging = getFirebaseMessaging();
      
      const message = {
        tokens,
        notification: {
          title: payload.title,
          body: payload.body,
          ...(payload.icon && { imageUrl: payload.icon })
        },
        data: payload.data || {},
        android: {
          priority: priority as any,
          notification: {
            ...(payload.icon && { icon: payload.icon }),
            ...(payload.badge && { badge: payload.badge.toString() })
          }
        },
        apns: {
          payload: {
            aps: {
              alert: {
                title: payload.title,
                body: payload.body
              },
              ...(payload.badge && { badge: payload.badge })
            }
          }
        }
      };

      const response = await messaging.sendEachForMulticast(message);
      
      const results = response.responses.map((result, index) => ({
        token: tokens[index],
        success: result.success,
        error: result.error?.message,
        messageId: result.messageId
      }));

      console.log(`📱 Firebase notifications sent: ${response.successCount}/${tokens.length}`);

      return {
        success: response.successCount > 0,
        sentCount: response.successCount,
        failedCount: response.failureCount,
        results
      };
    } catch (error) {
      console.error('❌ Firebase notification error:', error);
      return {
        success: false,
        sentCount: 0,
        failedCount: tokens.length,
        results: tokens.map(token => ({
          token,
          success: false,
          error: error instanceof Error ? error.message : 'Firebase error'
        }))
      };
    }
  }

  private async sendWebPushNotifications(
    subscriptions: string[], 
    payload: NotificationPayload
  ): Promise<NotificationResult> {
    if (!isWebPushReady()) {
      return {
        success: false,
        sentCount: 0,
        failedCount: subscriptions.length,
        results: subscriptions.map(sub => ({
          token: sub,
          success: false,
          error: 'Web Push not configured'
        }))
      };
    }

    try {
      const webpush = getWebPush();
      const pushData = JSON.stringify({
        title: payload.title,
        body: payload.body,
        icon: payload.icon,
        badge: payload.badge,
        data: payload.data
      });

      const results = await Promise.allSettled(
        subscriptions.map(async (subscription) => {
          try {
            const parsedSub = JSON.parse(subscription);
            await webpush.sendNotification(parsedSub, pushData);
            return {
              token: subscription,
              success: true
            };
          } catch (error) {
            return {
              token: subscription,
              success: false,
              error: error instanceof Error ? error.message : 'Web push error'
            };
          }
        })
      );

      const processedResults = results.map(result => 
        result.status === 'fulfilled' ? result.value : {
          token: '',
          success: false,
          error: 'Promise rejected'
        }
      );

      const sentCount = processedResults.filter(r => r.success).length;
      const failedCount = processedResults.length - sentCount;

      console.log(`🌐 Web push notifications sent: ${sentCount}/${subscriptions.length}`);

      return {
        success: sentCount > 0,
        sentCount,
        failedCount,
        results: processedResults
      };
    } catch (error) {
      console.error('❌ Web Push notification error:', error);
      return {
        success: false,
        sentCount: 0,
        failedCount: subscriptions.length,
        results: subscriptions.map(sub => ({
          token: sub,
          success: false,
          error: error instanceof Error ? error.message : 'Web push error'
        }))
      };
    }
  }

  private isMobileToken(token: string): boolean {
    // FCM tokens are typically longer and contain specific patterns
    // This is a simple heuristic - in production, you might store platform info with tokens
    return token.length > 140 && !token.startsWith('{');
  }

  private isWebToken(token: string): boolean {
    // Web push subscriptions are JSON objects
    try {
      const parsed = JSON.parse(token);
      return parsed.endpoint && parsed.keys;
    } catch {
      return false;
    }
  }

  async getQueueStats() {
    return this.queueService.getJobStats();
  }

  async retryFailedNotifications() {
    return this.queueService.retryFailedJobs();
  }
}