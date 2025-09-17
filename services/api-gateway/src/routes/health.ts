import { Router, Request, Response } from 'express';
import { ApiResponse } from '../../shared/types';

interface ServiceConfig {
  url: string;
  timeout: number;
}

interface ServiceStatus {
  name: string;
  url: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  responseTime?: number;
  error?: string;
  lastChecked: string;
}

export const createHealthRoutes = (services: Record<string, ServiceConfig>): Router => {
  const router = Router();

  // GET /api/health - Overall health check
  router.get('/', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const timestamp = new Date().toISOString();
      const serviceStatuses = await checkAllServices(services);
      
      const allHealthy = serviceStatuses.every(service => service.status === 'healthy');
      const overallStatus = allHealthy ? 'healthy' : 'degraded';
      
      res.status(allHealthy ? 200 : 503).json({
        success: allHealthy,
        data: {
          status: overallStatus,
          timestamp,
          services: serviceStatuses,
          gateway: {
            status: 'healthy',
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            version: '1.0.0'
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Health check error'
      });
    }
  });

  // GET /api/health/services - Detailed service health
  router.get('/services', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const serviceStatuses = await checkAllServices(services);
      
      res.json({
        success: true,
        data: {
          services: serviceStatuses,
          summary: {
            total: serviceStatuses.length,
            healthy: serviceStatuses.filter(s => s.status === 'healthy').length,
            unhealthy: serviceStatuses.filter(s => s.status === 'unhealthy').length
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Service health check error'
      });
    }
  });

  // GET /api/health/services/:serviceName - Individual service health
  router.get('/services/:serviceName', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { serviceName } = req.params;
      const serviceConfig = services[serviceName];
      
      if (!serviceConfig) {
        return res.status(404).json({
          success: false,
          error: `Service '${serviceName}' not found`
        });
      }

      const status = await checkService(serviceName, serviceConfig);
      
      res.status(status.status === 'healthy' ? 200 : 503).json({
        success: status.status === 'healthy',
        data: status
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Individual service health check error'
      });
    }
  });

  // GET /api/health/gateway - Gateway-specific health info
  router.get('/gateway', (req: Request, res: Response<ApiResponse>) => {
    try {
      const uptime = process.uptime();
      const memory = process.memoryUsage();
      
      res.json({
        success: true,
        data: {
          status: 'healthy',
          uptime: {
            seconds: uptime,
            human: formatUptime(uptime)
          },
          memory: {
            rss: formatBytes(memory.rss),
            heapTotal: formatBytes(memory.heapTotal),
            heapUsed: formatBytes(memory.heapUsed),
            external: formatBytes(memory.external)
          },
          process: {
            pid: process.pid,
            version: process.version,
            platform: process.platform,
            arch: process.arch
          },
          environment: {
            nodeEnv: process.env.NODE_ENV || 'development',
            port: process.env.PORT || '3000'
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Gateway health check error'
      });
    }
  });

  return router;
};

// Helper function to check all services
async function checkAllServices(services: Record<string, ServiceConfig>): Promise<ServiceStatus[]> {
  const checks = Object.entries(services).map(([name, config]) => 
    checkService(name, config)
  );
  
  return Promise.all(checks);
}

// Helper function to check individual service
async function checkService(name: string, config: ServiceConfig): Promise<ServiceStatus> {
  const startTime = Date.now();
  
  try {
    // Try to fetch health endpoint
    const healthUrl = `${config.url}/health`;
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.timeout);
    
    const response = await fetch(healthUrl, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'Accept': 'application/json'
      }
    });
    
    clearTimeout(timeoutId);
    const responseTime = Date.now() - startTime;
    
    if (response.ok) {
      return {
        name,
        url: config.url,
        status: 'healthy',
        responseTime,
        lastChecked: new Date().toISOString()
      };
    } else {
      return {
        name,
        url: config.url,
        status: 'unhealthy',
        responseTime,
        error: `HTTP ${response.status}: ${response.statusText}`,
        lastChecked: new Date().toISOString()
      };
    }
  } catch (error) {
    const responseTime = Date.now() - startTime;
    
    return {
      name,
      url: config.url,
      status: 'unhealthy',
      responseTime,
      error: error instanceof Error ? error.message : 'Unknown error',
      lastChecked: new Date().toISOString()
    };
  }
}

// Helper function to format uptime
function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0) parts.push(`${secs}s`);
  
  return parts.join(' ') || '0s';
}

// Helper function to format bytes
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}