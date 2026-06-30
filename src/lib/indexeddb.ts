// IndexedDB setup for offline data caching
const DB_NAME = 'AIMS_PWA_DB';
const DB_VERSION = 2;
const STORES = {
  items: 'items',
  transactions: 'transactions',
  categories: 'categories',
  suppliers: 'suppliers',
  scan_queue: 'scan_queue',
};

export class IndexedDBService {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = window.indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Create object stores
        if (!db.objectStoreNames.contains(STORES.items)) {
          db.createObjectStore(STORES.items, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(STORES.transactions)) {
          db.createObjectStore(STORES.transactions, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(STORES.categories)) {
          db.createObjectStore(STORES.categories, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(STORES.suppliers)) {
          db.createObjectStore(STORES.suppliers, { keyPath: 'id' });
        }

        // Create pending changes store for sync
        if (!db.objectStoreNames.contains('pending_changes')) {
          const pendingStore = db.createObjectStore('pending_changes', { keyPath: 'id', autoIncrement: true });
          pendingStore.createIndex('timestamp', 'timestamp');
        }

        // Create scan queue store for offline scan operations
        if (!db.objectStoreNames.contains(STORES.scan_queue)) {
          const scanQueueStore = db.createObjectStore(STORES.scan_queue, { keyPath: 'id', autoIncrement: true });
          scanQueueStore.createIndex('timestamp', 'timestamp');
          scanQueueStore.createIndex('barcode', 'barcode');
        }
      };
    });
  }

  async getAll<T>(storeName: string): Promise<T[]> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(storeName, 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.getAll();

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
  }

  async put<T>(storeName: string, data: T): Promise<void> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.put(data);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  async delete(storeName: string, key: string): Promise<void> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.delete(key);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  async clear(storeName: string): Promise<void> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.clear();

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  async addPendingChange(change: {
    type: 'create' | 'update' | 'delete';
    store: string;
    data: any;
    timestamp: number;
  }): Promise<void> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction('pending_changes', 'readwrite');
      const store = transaction.objectStore('pending_changes');
      const request = store.add(change);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  async getPendingChanges(): Promise<any[]> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction('pending_changes', 'readonly');
      const store = transaction.objectStore('pending_changes');
      const request = store.getAll();

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
  }

  async clearPendingChanges(): Promise<void> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction('pending_changes', 'readwrite');
      const store = transaction.objectStore('pending_changes');
      const request = store.clear();

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  // Scan queue methods
  async addScanEntry(scan: {
    barcode: string;
    action: 'add' | 'remove' | 'view';
    quantity?: number;
    timestamp: number;
    synced: boolean;
  }): Promise<void> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORES.scan_queue, 'readwrite');
      const store = transaction.objectStore(STORES.scan_queue);
      const request = store.add(scan);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve();
    });
  }

  async getScanQueue(): Promise<any[]> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORES.scan_queue, 'readonly');
      const store = transaction.objectStore(STORES.scan_queue);
      const index = store.index('timestamp');
      const request = index.getAll();

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
  }

  async markScanSynced(id: number): Promise<void> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORES.scan_queue, 'readwrite');
      const store = transaction.objectStore(STORES.scan_queue);
      const request = store.get(id);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const data = request.result;
        if (data) {
          data.synced = true;
          const updateRequest = store.put(data);
          updateRequest.onerror = () => reject(updateRequest.error);
          updateRequest.onsuccess = () => resolve();
        } else {
          resolve();
        }
      };
    });
  }

  async clearSyncedScans(): Promise<void> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORES.scan_queue, 'readwrite');
      const store = transaction.objectStore(STORES.scan_queue);
      const index = store.index('timestamp');
      const request = index.openCursor();

      request.onerror = () => reject(request.error);
      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (cursor) {
          const data = cursor.value;
          if (data.synced) {
            cursor.delete();
            cursor.continue();
          } else {
            cursor.continue();
          }
        } else {
          resolve();
        }
      };
    });
  }

  async getUnsyncedScans(): Promise<any[]> {
    if (!this.db) await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORES.scan_queue, 'readonly');
      const store = transaction.objectStore(STORES.scan_queue);
      const request = store.getAll();

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const allScans = request.result;
        const unsynced = allScans.filter((scan: any) => !scan.synced);
        resolve(unsynced);
      };
    });
  }
}

export const indexedDB = new IndexedDBService();
