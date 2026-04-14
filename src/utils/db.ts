const DB_NAME = 'HackerDevDB';
const DB_VERSION = 1;

export interface Target {
    id?: number;
    name: string;
    url: string;
    description: string;
    created_at: string;
}

export interface ScanResultData {
    id?: number;
    targetId: number;
    url: string;
    timestamp: string;
    data: any; // Scanner results (secrets, forms, comments, etc.)
}

class HackerDevDB {
    private db: IDBDatabase | null = null;

    async init(): Promise<IDBDatabase> {
        return new Promise((resolve, reject) => {
            if (this.db) return resolve(this.db);

            const request = indexedDB.open(DB_NAME, DB_VERSION);

            request.onerror = (event: any) => {
                console.error("IndexedDB error:", event.target.error);
                reject(event.target.error);
            };

            request.onsuccess = (event: any) => {
                this.db = event.target.result;
                resolve(this.db!);
            };

            request.onupgradeneeded = (event: any) => {
                const db = event.target.result;

                // Targets Store
                if (!db.objectStoreNames.contains('targets')) {
                    const targetStore = db.createObjectStore('targets', { keyPath: 'id', autoIncrement: true });
                    targetStore.createIndex('name', 'name', { unique: false });
                    targetStore.createIndex('url', 'url', { unique: true });
                }

                // Scans Store
                if (!db.objectStoreNames.contains('scans')) {
                    const scanStore = db.createObjectStore('scans', { keyPath: 'id', autoIncrement: true });
                    scanStore.createIndex('targetId', 'targetId', { unique: false });
                    scanStore.createIndex('timestamp', 'timestamp', { unique: false });
                }
            };
        });
    }

    // --- Targets ---

    async getOrCreateTarget(url: string, name?: string): Promise<number> {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction(['targets'], 'readwrite');
            const store = transaction.objectStore('targets');
            const index = store.index('url');
            const getRequest = index.get(url);

            getRequest.onsuccess = () => {
                if (getRequest.result) {
                    resolve(getRequest.result.id);
                } else {
                    const addRequest = store.add({
                        name: name || new URL(url).hostname,
                        url,
                        description: '',
                        created_at: new Date().toISOString()
                    });
                    addRequest.onsuccess = (e: any) => resolve(e.target.result);
                    addRequest.onerror = () => reject(addRequest.error);
                }
            };
            getRequest.onerror = () => reject(getRequest.error);
        });
    }

    async getAllTargets(): Promise<Target[]> {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction(['targets'], 'readonly');
            const store = transaction.objectStore('targets');
            const request = store.getAll();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    // --- Scans ---

    async saveScan(targetId: number, url: string, data: any): Promise<number> {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction(['scans'], 'readwrite');
            const store = transaction.objectStore('scans');
            const request = store.add({
                targetId,
                url,
                timestamp: new Date().toISOString(),
                data
            });
            request.onsuccess = (e: any) => resolve(e.target.result);
            request.onerror = () => reject(request.error);
        });
    }

    async getScansByTarget(targetId: number): Promise<ScanResultData[]> {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction(['scans'], 'readonly');
            const store = transaction.objectStore('scans');
            const index = store.index('targetId');
            const request = index.getAll(IDBKeyRange.only(targetId));
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async deleteScan(id: number): Promise<void> {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db!.transaction(['scans'], 'readwrite');
            const store = transaction.objectStore('scans');
            const request = store.delete(id);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
}

export const db = new HackerDevDB();
