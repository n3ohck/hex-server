# Ejemplos de Integración con Clientes

Este documento proporciona ejemplos prácticos para integrar los microservicios con diferentes tipos de clientes.

## 📱 React Native

### Configuración Inicial

```bash
# Instalar dependencias necesarias
npm install @react-native-firebase/app @react-native-firebase/messaging
npm install @react-native-async-storage/async-storage

# Para iOS, también instalar pods
cd ios && pod install
```

### Configuración de Firebase

```javascript
// firebase.js
import { AppRegistry } from 'react-native';
import messaging from '@react-native-firebase/messaging';

// Background message handler
messaging().setBackgroundMessageHandler(async remoteMessage => {
  console.log('Message handled in the background!', remoteMessage);
});

// Register the app
AppRegistry.registerComponent('YourApp', () => App);
```

### Servicio de Notificaciones

```javascript
// services/NotificationService.js
import messaging from '@react-native-firebase/messaging';
import AsyncStorage from '@react-native-async-storage/async-storage';

const API_BASE = 'http://your-api-gateway.com/api';

class NotificationService {
  async initialize() {
    // Solicitar permisos
    const authStatus = await messaging().requestPermission();
    
    if (authStatus === messaging.AuthorizationStatus.AUTHORIZED ||
        authStatus === messaging.AuthorizationStatus.PROVISIONAL) {
      
      // Obtener token FCM
      const token = await messaging().getToken();
      await this.registerDevice(token);
      
      // Configurar listeners
      this.setupMessageListeners();
    }
  }

  async registerDevice(token) {
    try {
      const userId = await AsyncStorage.getItem('userId');
      const authToken = await AsyncStorage.getItem('authToken');
      
      const response = await fetch(`${API_BASE}/notifications/devices/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({
          token,
          platform: Platform.OS,
          userId
        })
      });
      
      const result = await response.json();
      console.log('Device registered:', result);
    } catch (error) {
      console.error('Error registering device:', error);
    }
  }

  setupMessageListeners() {
    // Mensaje en primer plano
    messaging().onMessage(async remoteMessage => {
      console.log('Foreground message:', remoteMessage);
      
      // Mostrar notificación local o actualizar UI
      this.showLocalNotification(remoteMessage);
    });

    // Notificación tocada (app abierta)
    messaging().onNotificationOpenedApp(remoteMessage => {
      console.log('Notification caused app to open:', remoteMessage);
      this.handleNotificationNavigation(remoteMessage);
    });

    // App abierta desde notificación (app cerrada)
    messaging()
      .getInitialNotification()
      .then(remoteMessage => {
        if (remoteMessage) {
          console.log('App opened from notification:', remoteMessage);
          this.handleNotificationNavigation(remoteMessage);
        }
      });
  }

  showLocalNotification(remoteMessage) {
    // Implementar usando react-native-push-notification o similar
    // O mostrar un banner/modal personalizado
  }

  handleNotificationNavigation(remoteMessage) {
    // Navegar basado en los datos de la notificación
    const { data } = remoteMessage;
    
    if (data?.screen) {
      // Navegar a pantalla específica
      // navigation.navigate(data.screen, data.params);
    }
  }
}

export default new NotificationService();
```

### Hook de React para Datos en Tiempo Real

```javascript
// hooks/useRealtimeData.js
import { useState, useEffect } from 'react';
import io from 'socket.io-client';

export const useRealtimeData = (serverUrl) => {
  const [socket, setSocket] = useState(null);
  const [tcpData, setTcpData] = useState([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const newSocket = io(serverUrl);
    
    newSocket.on('connect', () => {
      setIsConnected(true);
      console.log('Connected to real-time server');
    });

    newSocket.on('disconnect', () => {
      setIsConnected(false);
      console.log('Disconnected from real-time server');
    });

    newSocket.on('tcp:data', (data) => {
      setTcpData(prevData => [data, ...prevData.slice(0, 99)]); // Keep last 100
    });

    newSocket.on('tcp:connection', (data) => {
      console.log('New TCP connection:', data);
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, [serverUrl]);

  const joinRoom = (room) => {
    if (socket) {
      socket.emit('join-room', room);
    }
  };

  const leaveRoom = (room) => {
    if (socket) {
      socket.emit('leave-room', room);
    }
  };

  return {
    socket,
    tcpData,
    isConnected,
    joinRoom,
    leaveRoom
  };
};
```

### Componente de Monitoreo

```javascript
// components/TcpMonitor.js
import React, { useEffect } from 'react';
import { View, Text, FlatList, StyleSheet } from 'react-native';
import { useRealtimeData } from '../hooks/useRealtimeData';

const TcpMonitor = () => {
  const { tcpData, isConnected, joinRoom } = useRealtimeData('http://your-api-gateway.com');

  useEffect(() => {
    joinRoom('tcp-monitoring');
  }, []);

  const renderTcpItem = ({ item }) => (
    <View style={styles.tcpItem}>
      <Text style={styles.timestamp}>{new Date(item.timestamp).toLocaleTimeString()}</Text>
      <Text style={styles.clientIP}>{item.clientIP}</Text>
      <Text style={styles.hexData}>{item.hexData}</Text>
      <Text style={styles.asciiData}>{item.asciiData}</Text>
    </View>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>TCP Monitor</Text>
        <View style={[styles.status, { backgroundColor: isConnected ? 'green' : 'red' }]}>
          <Text style={styles.statusText}>{isConnected ? 'Connected' : 'Disconnected'}</Text>
        </View>
      </View>
      
      <FlatList
        data={tcpData}
        renderItem={renderTcpItem}
        keyExtractor={(item) => item.id}
        style={styles.list}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  title: {
    fontSize: 20,
    fontWeight: 'bold',
  },
  status: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
  },
  statusText: {
    color: 'white',
    fontSize: 12,
  },
  list: {
    flex: 1,
  },
  tcpItem: {
    backgroundColor: '#f5f5f5',
    padding: 12,
    marginBottom: 8,
    borderRadius: 4,
  },
  timestamp: {
    fontSize: 12,
    color: '#666',
  },
  clientIP: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
  },
  hexData: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: '#007acc',
  },
  asciiData: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: '#666',
  },
});

export default TcpMonitor;
```

## 🌐 Aplicación Web (React)

### Service Worker para Web Push

```javascript
// public/sw.js
self.addEventListener('push', function(event) {
  if (event.data) {
    const data = event.data.json();
    
    const options = {
      body: data.body,
      icon: data.icon || '/icon-192x192.png',
      badge: '/badge-72x72.png',
      data: data.data,
      actions: [
        {
          action: 'view',
          title: 'Ver',
          icon: '/icon-view.png'
        },
        {
          action: 'dismiss',
          title: 'Descartar',
          icon: '/icon-dismiss.png'
        }
      ]
    };

    event.waitUntil(
      self.registration.showNotification(data.title, options)
    );
  }
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();

  if (event.action === 'view') {
    event.waitUntil(
      clients.openWindow(event.notification.data.url || '/')
    );
  }
});
```

### Servicio de Notificaciones Web

```javascript
// services/WebPushService.js
class WebPushService {
  constructor(apiBase) {
    this.apiBase = apiBase;
  }

  async initialize() {
    if ('serviceWorker' in navigator && 'PushManager' in window) {
      try {
        const registration = await navigator.serviceWorker.register('/sw.js');
        console.log('Service Worker registered:', registration);
        
        const permission = await this.requestPermission();
        if (permission === 'granted') {
          await this.subscribeUser(registration);
        }
      } catch (error) {
        console.error('Service Worker registration failed:', error);
      }
    }
  }

  async requestPermission() {
    const permission = await Notification.requestPermission();
    return permission;
  }

  async subscribeUser(registration) {
    try {
      // Obtener clave pública VAPID
      const response = await fetch(`${this.apiBase}/notifications/web-push/vapid-public-key`);
      const { data } = await response.json();
      
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: data.publicKey
      });

      // Registrar suscripción en el servidor
      await this.registerSubscription(subscription);
      
      return subscription;
    } catch (error) {
      console.error('Failed to subscribe user:', error);
    }
  }

  async registerSubscription(subscription) {
    try {
      const authToken = localStorage.getItem('authToken');
      
      const response = await fetch(`${this.apiBase}/notifications/web-push/subscribe`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({ subscription })
      });

      const result = await response.json();
      console.log('Subscription registered:', result);
    } catch (error) {
      console.error('Error registering subscription:', error);
    }
  }

  async sendTestNotification() {
    try {
      const authToken = localStorage.getItem('authToken');
      
      const response = await fetch(`${this.apiBase}/notifications/notifications/test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({
          deviceToken: JSON.stringify(await this.getCurrentSubscription()),
          platform: 'web'
        })
      });

      const result = await response.json();
      console.log('Test notification sent:', result);
    } catch (error) {
      console.error('Error sending test notification:', error);
    }
  }

  async getCurrentSubscription() {
    const registration = await navigator.serviceWorker.ready;
    return registration.pushManager.getSubscription();
  }
}

export default WebPushService;
```

### Componente React para Datos en Tiempo Real

```javascript
// components/RealtimeDataViewer.jsx
import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';

const RealtimeDataViewer = ({ apiUrl }) => {
  const [socket, setSocket] = useState(null);
  const [data, setData] = useState([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const newSocket = io(apiUrl);
    
    newSocket.on('connect', () => {
      setIsConnected(true);
      newSocket.emit('join-room', 'tcp-monitoring');
    });

    newSocket.on('disconnect', () => setIsConnected(false));
    
    newSocket.on('tcp:data', (newData) => {
      setData(prevData => [newData, ...prevData.slice(0, 49)]); // Keep last 50
    });

    setSocket(newSocket);

    return () => newSocket.close();
  }, [apiUrl]);

  return (
    <div className=\"realtime-viewer\">
      <div className=\"header\">
        <h2>Datos TCP en Tiempo Real</h2>
        <div className={`status ${isConnected ? 'connected' : 'disconnected'}`}>
          {isConnected ? '🟢 Conectado' : '🔴 Desconectado'}
        </div>
      </div>
      
      <div className=\"data-list\">
        {data.map((item, index) => (
          <div key={item.id || index} className=\"data-item\">
            <div className=\"timestamp\">{new Date(item.timestamp).toLocaleString()}</div>
            <div className=\"client-ip\">{item.clientIP}</div>
            <div className=\"hex-data\">{item.hexData}</div>
            <div className=\"ascii-data\">{item.asciiData}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RealtimeDataViewer;
```

## 🔧 Cliente TCP (Pruebas)

### Script de Prueba en Node.js

```javascript
// test-tcp-client.js
const net = require('net');

class TcpTestClient {
  constructor(host = 'localhost', port = 9000) {
    this.host = host;
    this.port = port;
    this.client = null;
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.client = net.createConnection(this.port, this.host);
      
      this.client.on('connect', () => {
        console.log(`✅ Conectado a ${this.host}:${this.port}`);
        resolve();
      });

      this.client.on('error', (err) => {
        console.error('❌ Error de conexión:', err.message);
        reject(err);
      });

      this.client.on('close', () => {
        console.log('🔌 Conexión cerrada');
      });
    });
  }

  sendData(data) {
    if (this.client && !this.client.destroyed) {
      this.client.write(data);
      console.log(`📤 Enviado: ${data}`);
    }
  }

  sendHex(hexString) {
    const buffer = Buffer.from(hexString, 'hex');
    if (this.client && !this.client.destroyed) {
      this.client.write(buffer);
      console.log(`📤 Enviado (hex): ${hexString}`);
    }
  }

  disconnect() {
    if (this.client) {
      this.client.end();
    }
  }
}

// Ejemplo de uso
async function testTcpConnection() {
  const client = new TcpTestClient();
  
  try {
    await client.connect();
    
    // Enviar datos de prueba
    client.sendData('Hello TCP Server!');
    client.sendHex('48656c6c6f20576f726c64'); // \"Hello World\" en hex
    
    // Simular datos periódicos
    const interval = setInterval(() => {
      const timestamp = new Date().toISOString();
      client.sendData(`Datos de prueba - ${timestamp}`);
    }, 5000);

    // Desconectar después de 30 segundos
    setTimeout(() => {
      clearInterval(interval);
      client.disconnect();
    }, 30000);
    
  } catch (error) {
    console.error('Error en prueba TCP:', error);
  }
}

// Ejecutar si es llamado directamente
if (require.main === module) {
  testTcpConnection();
}

module.exports = TcpTestClient;
```

### Script de Bash para Pruebas

```bash
#!/bin/bash
# test-tcp.sh

HOST=${1:-localhost}
PORT=${2:-9000}

echo \"🧪 Probando conexión TCP a $HOST:$PORT\"

# Prueba básica con netcat
echo \"📤 Enviando mensaje de prueba...\"
echo \"Test message from bash script\" | nc $HOST $PORT

# Enviar datos hex
echo \"📤 Enviando datos hex...\"
echo -ne '\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64' | nc $HOST $PORT

# Datos con timestamp
echo \"📤 Enviando datos con timestamp...\"
echo \"Test data - $(date)\" | nc $HOST $PORT

echo \"✅ Pruebas TCP completadas\"
```

## 🌍 Ejemplos de Autenticación

### Login y Gestión de Tokens

```javascript
// auth/AuthService.js
class AuthService {
  constructor(apiBase) {
    this.apiBase = apiBase;
    this.token = localStorage.getItem('authToken');
  }

  async login(username, password) {
    try {
      const response = await fetch(`${this.apiBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const result = await response.json();
      
      if (result.success) {
        this.token = result.data.token;
        localStorage.setItem('authToken', this.token);
        localStorage.setItem('user', JSON.stringify(result.data.user));
        return result.data;
      } else {
        throw new Error(result.error);
      }
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  }

  async register(username, password, role = 'user') {
    try {
      const response = await fetch(`${this.apiBase}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role })
      });

      const result = await response.json();
      
      if (result.success) {
        this.token = result.data.token;
        localStorage.setItem('authToken', this.token);
        localStorage.setItem('user', JSON.stringify(result.data.user));
        return result.data;
      } else {
        throw new Error(result.error);
      }
    } catch (error) {
      console.error('Register error:', error);
      throw error;
    }
  }

  logout() {
    this.token = null;
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
  }

  getAuthHeaders() {
    return {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json'
    };
  }

  isAuthenticated() {
    return !!this.token;
  }

  getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  }
}

export default AuthService;
```

Estos ejemplos cubren las integraciones más comunes. Para casos específicos, revisa la documentación de la API en `/api/health` o contacta al equipo de desarrollo.