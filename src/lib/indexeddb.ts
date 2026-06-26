// IndexedDB setup for offline data caching
const DB_NAME = 'AIMS_PWA_DB';
const DB_VERSION = 1;
const STORES = {
  items: 'items',
  transactions: 'transactions',
  categories: 'categories',
  suppliers: 'suppliers',
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
}

export const indexedDB = new IndexedDBService();
