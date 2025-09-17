import admin from 'firebase-admin';

let firebaseApp: admin.app.App | null = null;

export const initializeFirebase = (): admin.app.App => {
  if (firebaseApp) {
    return firebaseApp;
  }

  try {
    // Check if Firebase service account key is provided
    const serviceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
    
    if (serviceAccountKey) {
      // Initialize with service account key
      const serviceAccount = JSON.parse(serviceAccountKey);
      firebaseApp = admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      });
    } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      // Initialize with application default credentials
      firebaseApp = admin.initializeApp({
        credential: admin.credential.applicationDefault()
      });
    } else {
      console.warn('⚠️  Firebase not configured. Push notifications will be disabled.');
      console.warn('   Set FIREBASE_SERVICE_ACCOUNT_KEY or GOOGLE_APPLICATION_CREDENTIALS');
      return null as any;
    }

    console.log('🔥 Firebase initialized successfully');
    return firebaseApp;
  } catch (error) {
    console.error('❌ Failed to initialize Firebase:', error);
    return null as any;
  }
};

export const getFirebaseApp = (): admin.app.App => {
  if (!firebaseApp) {
    return initializeFirebase();
  }
  return firebaseApp;
};

export const getFirebaseMessaging = (): admin.messaging.Messaging => {
  const app = getFirebaseApp();
  if (!app) {
    throw new Error('Firebase not initialized');
  }
  return admin.messaging(app);
};