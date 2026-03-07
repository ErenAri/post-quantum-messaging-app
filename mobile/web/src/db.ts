/**
 * IndexedDB message store for local persistence.
 * Messages are stored per-conversation and loaded instantly from disk.
 */

export type StoredMessage = {
  id: string;
  conversationId: string;
  sender: string;
  recipient: string;
  text: string;
  timestamp: number;
  status: "sending" | "sent" | "delivered" | "failed";
  serverMessageId?: number;
};

const DB_NAME = "pqmsg-web";
const DB_VERSION = 1;
const MESSAGES_STORE = "messages";

let dbInstance: IDBDatabase | null = null;

function open(): Promise<IDBDatabase> {
  if (dbInstance) return Promise.resolve(dbInstance);
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(MESSAGES_STORE)) {
        const store = db.createObjectStore(MESSAGES_STORE, { keyPath: "id" });
        store.createIndex("by_conversation", "conversationId", { unique: false });
        store.createIndex("by_timestamp", ["conversationId", "timestamp"], { unique: false });
      }
    };
    request.onsuccess = () => {
      dbInstance = request.result;
      resolve(dbInstance);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function saveMessage(msg: StoredMessage): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readwrite");
    tx.objectStore(MESSAGES_STORE).put(msg);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function updateMessageStatus(
  id: string,
  status: StoredMessage["status"],
  serverMessageId?: number
): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readwrite");
    const store = tx.objectStore(MESSAGES_STORE);
    const get = store.get(id);
    get.onsuccess = () => {
      const msg = get.result as StoredMessage | undefined;
      if (msg) {
        msg.status = status;
        if (serverMessageId !== undefined) msg.serverMessageId = serverMessageId;
        store.put(msg);
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getMessages(conversationId: string): Promise<StoredMessage[]> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readonly");
    const index = tx.objectStore(MESSAGES_STORE).index("by_conversation");
    const request = index.getAll(conversationId);
    request.onsuccess = () => {
      const msgs = (request.result as StoredMessage[]).sort(
        (a, b) => a.timestamp - b.timestamp
      );
      resolve(msgs);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function clearConversationMessages(conversationId: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readwrite");
    const store = tx.objectStore(MESSAGES_STORE);
    const index = store.index("by_conversation");
    const request = index.openCursor(conversationId);
    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function clearAllMessages(): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readwrite");
    tx.objectStore(MESSAGES_STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
