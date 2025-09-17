import { DeviceToken } from '../../shared/types';
import { generateId } from '../../shared/utils';

// In-memory storage for demo purposes
// In production, use a proper database (MongoDB, PostgreSQL, etc.)
export class DeviceService {
  private devices: Map<string, DeviceToken> = new Map();

  async registerDevice(token: string, platform: 'ios' | 'android' | 'web', userId?: string): Promise<DeviceToken> {
    const deviceId = generateId();
    const device: DeviceToken = {
      id: deviceId,
      token,
      platform,
      userId,
      createdAt: new Date().toISOString(),
      isActive: true
    };

    this.devices.set(deviceId, device);
    console.log(`📱 Device registered: ${platform} - ${deviceId}`);
    
    return device;
  }

  async getDevice(deviceId: string): Promise<DeviceToken | null> {
    return this.devices.get(deviceId) || null;
  }

  async getDevicesByUser(userId: string): Promise<DeviceToken[]> {
    return Array.from(this.devices.values())
      .filter(device => device.userId === userId && device.isActive);
  }

  async getDevicesByPlatform(platform: 'ios' | 'android' | 'web'): Promise<DeviceToken[]> {
    return Array.from(this.devices.values())
      .filter(device => device.platform === platform && device.isActive);
  }

  async getAllActiveDevices(): Promise<DeviceToken[]> {
    return Array.from(this.devices.values())
      .filter(device => device.isActive);
  }

  async updateDevice(deviceId: string, updates: Partial<DeviceToken>): Promise<DeviceToken | null> {
    const device = this.devices.get(deviceId);
    if (!device) return null;

    const updatedDevice = { ...device, ...updates };
    this.devices.set(deviceId, updatedDevice);
    
    return updatedDevice;
  }

  async deactivateDevice(deviceId: string): Promise<boolean> {
    const device = this.devices.get(deviceId);
    if (!device) return false;

    device.isActive = false;
    this.devices.set(deviceId, device);
    console.log(`📱 Device deactivated: ${deviceId}`);
    
    return true;
  }

  async removeDevice(deviceId: string): Promise<boolean> {
    const removed = this.devices.delete(deviceId);
    if (removed) {
      console.log(`📱 Device removed: ${deviceId}`);
    }
    return removed;
  }

  async removeDeviceByToken(token: string): Promise<boolean> {
    for (const [id, device] of this.devices.entries()) {
      if (device.token === token) {
        this.devices.delete(id);
        console.log(`📱 Device removed by token: ${id}`);
        return true;
      }
    }
    return false;
  }

  async getStats(): Promise<{
    total: number;
    active: number;
    byPlatform: Record<string, number>;
  }> {
    const devices = Array.from(this.devices.values());
    const active = devices.filter(d => d.isActive);
    
    const byPlatform = devices.reduce((acc, device) => {
      acc[device.platform] = (acc[device.platform] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      total: devices.length,
      active: active.length,
      byPlatform
    };
  }

  // Clean up inactive devices
  async cleanupInactiveDevices(daysOld: number = 30): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    let removedCount = 0;
    
    for (const [id, device] of this.devices.entries()) {
      const createdAt = new Date(device.createdAt);
      if (!device.isActive && createdAt < cutoffDate) {
        this.devices.delete(id);
        removedCount++;
      }
    }

    if (removedCount > 0) {
      console.log(`🧹 Cleaned up ${removedCount} inactive devices`);
    }

    return removedCount;
  }
}