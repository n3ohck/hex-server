import Queue from 'bull';
import { NotificationRequest } from '../../shared/types';

export class QueueService {
  private notificationQueue: Queue.Queue<NotificationRequest>;
  private redisConfig: any;

  constructor() {
    // Redis configuration
    this.redisConfig = {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB || '0')
    };

    // Initialize queue
    this.notificationQueue = new Queue('notification queue', {
      redis: this.redisConfig,
      defaultJobOptions: {
        removeOnComplete: 100,
        removeOnFail: 50,
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000
        }
      }
    });

    this.setupProcessors();
    this.setupEventHandlers();
  }

  private setupProcessors(): void {
    // Process notification jobs
    this.notificationQueue.process('send-notification', async (job) => {
      const { deviceTokens, payload, priority } = job.data;
      console.log(`📤 Processing notification job: ${job.id}`);
      
      // This will be handled by the NotificationService
      // The actual sending logic is implemented there
      return { processed: true, tokenCount: deviceTokens.length };
    });
  }

  private setupEventHandlers(): void {
    this.notificationQueue.on('completed', (job, result) => {
      console.log(`✅ Notification job ${job.id} completed:`, result);
    });

    this.notificationQueue.on('failed', (job, err) => {
      console.error(`❌ Notification job ${job.id} failed:`, err.message);
    });

    this.notificationQueue.on('stalled', (job) => {
      console.warn(`⏸️  Notification job ${job.id} stalled`);
    });
  }

  async addNotificationJob(request: NotificationRequest, options?: Queue.JobOptions): Promise<Queue.Job<NotificationRequest>> {
    const jobOptions = {
      priority: request.priority === 'high' ? 1 : 5,
      delay: 0,
      ...options
    };

    return this.notificationQueue.add('send-notification', request, jobOptions);
  }

  async addBulkNotificationJobs(requests: NotificationRequest[]): Promise<Queue.Job<NotificationRequest>[]> {
    const jobs = requests.map(request => ({
      name: 'send-notification',
      data: request,
      opts: {
        priority: request.priority === 'high' ? 1 : 5
      }
    }));

    return this.notificationQueue.addBulk(jobs) as Promise<Queue.Job<NotificationRequest>[]>;
  }

  async getJobStats(): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
    delayed: number;
  }> {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.notificationQueue.getWaiting(),
      this.notificationQueue.getActive(),
      this.notificationQueue.getCompleted(),
      this.notificationQueue.getFailed(),
      this.notificationQueue.getDelayed()
    ]);

    return {
      waiting: waiting.length,
      active: active.length,
      completed: completed.length,
      failed: failed.length,
      delayed: delayed.length
    };
  }

  async getJob(jobId: string): Promise<Queue.Job<NotificationRequest> | null> {
    return this.notificationQueue.getJob(jobId);
  }

  async removeJob(jobId: string): Promise<void> {
    const job = await this.getJob(jobId);
    if (job) {
      await job.remove();
    }
  }

  async retryFailedJobs(): Promise<number> {
    const failedJobs = await this.notificationQueue.getFailed();
    let retriedCount = 0;

    for (const job of failedJobs) {
      try {
        await job.retry();
        retriedCount++;
      } catch (error) {
        console.error(`Failed to retry job ${job.id}:`, error);
      }
    }

    console.log(`🔄 Retried ${retriedCount} failed jobs`);
    return retriedCount;
  }

  async cleanOldJobs(grace: number = 24 * 60 * 60 * 1000): Promise<void> {
    await this.notificationQueue.clean(grace, 'completed');
    await this.notificationQueue.clean(grace, 'failed');
    console.log(`🧹 Cleaned jobs older than ${grace}ms`);
  }

  async pauseQueue(): Promise<void> {
    await this.notificationQueue.pause();
    console.log('⏸️  Notification queue paused');
  }

  async resumeQueue(): Promise<void> {
    await this.notificationQueue.resume();
    console.log('▶️  Notification queue resumed');
  }

  async close(): Promise<void> {
    await this.notificationQueue.close();
    console.log('🔒 Notification queue closed');
  }

  getQueue(): Queue.Queue<NotificationRequest> {
    return this.notificationQueue;
  }
}