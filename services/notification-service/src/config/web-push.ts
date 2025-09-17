import webpush from 'web-push';

let isWebPushConfigured = false;

export const initializeWebPush = (): void => {
  const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
  const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
  const vapidSubject = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';

  if (vapidPublicKey && vapidPrivateKey) {
    webpush.setVapidDetails(
      vapidSubject,
      vapidPublicKey,
      vapidPrivateKey
    );
    isWebPushConfigured = true;
    console.log('🌐 Web Push configured successfully');
  } else {
    console.warn('⚠️  Web Push not configured. Set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY');
    console.warn('   Generate VAPID keys at: https://web-push-codelab.glitch.me/');
  }
};

export const getWebPush = () => {
  if (!isWebPushConfigured) {
    throw new Error('Web Push not configured');
  }
  return webpush;
};

export const isWebPushReady = (): boolean => {
  return isWebPushConfigured;
};

// Generate VAPID keys if needed (for development)
export const generateVapidKeys = () => {
  return webpush.generateVAPIDKeys();
};