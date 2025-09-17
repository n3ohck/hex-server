// Shared TypeScript types for all microservices

export interface HexLog {
  id: string;
  timestamp: string;
  clientIP: string;
  dataLength: number;
  hexData: string;
  asciiData: string;
  fileName: string;
}

export interface NotificationPayload {
  title: string;
  body: string;
  data?: Record<string, any>;
  icon?: string;
  badge?: number;
}

export interface DeviceToken {
  id: string;
  token: string;
  platform: 'ios' | 'android' | 'web';
  userId?: string;
  createdAt: string;
  isActive: boolean;
}

export interface NotificationRequest {
  deviceTokens: string[];
  payload: NotificationPayload;
  priority?: 'high' | 'normal';
  collapseKey?: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginationQuery {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface HexLogQuery extends PaginationQuery {
  clientIP?: string;
  startDate?: string;
  endDate?: string;
}