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
  // B1: Media preview fields
  fileId?: string;
  mimeType?: string;
  fileName?: string;
  attachmentDataBase64?: string;
  attachmentByteLength?: number;
  attachmentNoteText?: string;
  // B2: Rich interactions
  replyToId?: string;
  replyPreview?: string;
  reactions?: Array<{ emoji: string; sender: string }>;
  editedAt?: number;
  contentType?: "text" | "reply" | "reaction" | "edit";
};

const DB_NAME = "pqmsg-web";
const DB_VERSION = 6;
const MESSAGES_STORE = "messages";
const OUTBOX_STORE = "outbox";
const SESSIONS_STORE = "sessions";
const METADATA_STORE = "metadata";
const KEYS_STORE = "keys";

export type OutboxMessage = {
  id: string;
  userId: string;
  peerId: string;
  groupId?: string;
  text: string;
  timestamp: number;
  sealed: boolean;
  ephemeralTtl: number;
};

type StoredSession = {
  id: string;
  userId: string;
  peerId: string;
  sealedSession: string;
  updatedAt: number;
};

type StoredMetadata = {
  id: string;
  rawJson: string;
  updatedAt: number;
};

type StoredKeyRecord = {
  id: string;
  sealedKeys: string;
  updatedAt: number;
};

function searchableMessageText(message: StoredMessage): string {
  const parts = new Set<string>();
  const body = message.text.trim();
  if (body) {
    parts.add(body);
  }
  const fileName = message.fileName?.trim() || "";
  const mimeType = message.mimeType?.trim() || "";
  const noteText = message.attachmentNoteText?.trim() || "";
  if (fileName) {
    parts.add(fileName);
  }
  if (mimeType) {
    parts.add(mimeType);
    if (mimeType.startsWith("image/")) parts.add("photo");
    if (mimeType.startsWith("video/")) parts.add("video");
    if (mimeType.startsWith("audio/")) parts.add("audio");
    if (mimeType === "application/pdf") parts.add("pdf");
    if (
      !mimeType.startsWith("image/") &&
      !mimeType.startsWith("video/") &&
      !mimeType.startsWith("audio/") &&
      mimeType !== "application/pdf"
    ) {
      parts.add("document");
    }
  }
  if (noteText) {
    parts.add(noteText);
  }
  return Array.from(parts).join("\n");
}

let dbInstance: IDBDatabase | null = null;

function open(): Promise<IDBDatabase> {
  if (dbInstance) return Promise.resolve(dbInstance);
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = request.result;
      if (!db.objectStoreNames.contains(MESSAGES_STORE)) {
        const store = db.createObjectStore(MESSAGES_STORE, { keyPath: "id" });
        store.createIndex("by_conversation", "conversationId", { unique: false });
        store.createIndex("by_timestamp", ["conversationId", "timestamp"], { unique: false });
      }
      if (!db.objectStoreNames.contains(OUTBOX_STORE)) {
        db.createObjectStore(OUTBOX_STORE, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(SESSIONS_STORE)) {
        const store = db.createObjectStore(SESSIONS_STORE, { keyPath: "id" });
        store.createIndex("by_user", "userId", { unique: false });
      }
      if (!db.objectStoreNames.contains(METADATA_STORE)) {
        db.createObjectStore(METADATA_STORE, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(KEYS_STORE)) {
        db.createObjectStore(KEYS_STORE, { keyPath: "id" });
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

export async function saveMessageIfAbsent(msg: StoredMessage): Promise<boolean> {
  const db = await open();
  return new Promise((resolve, reject) => {
    let inserted = false;
    const tx = db.transaction(MESSAGES_STORE, "readwrite");
    const request = tx.objectStore(MESSAGES_STORE).add(msg);
    request.onsuccess = () => {
      inserted = true;
    };
    request.onerror = (event) => {
      if (request.error?.name === "ConstraintError") {
        event.preventDefault();
        event.stopPropagation();
        return;
      }
    };
    tx.oncomplete = () => resolve(inserted);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => {
      if (tx.error?.name === "ConstraintError") {
        resolve(false);
        return;
      }
      reject(tx.error);
    };
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

export async function deleteMessages(ids: string[]): Promise<void> {
  if (ids.length === 0) {
    return;
  }
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readwrite");
    const store = tx.objectStore(MESSAGES_STORE);
    for (const id of ids) {
      store.delete(id);
    }
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

export async function searchMessages(query: string): Promise<StoredMessage[]> {
  const db = await open();
  const lower = query.toLowerCase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readonly");
    const store = tx.objectStore(MESSAGES_STORE);
    const results: StoredMessage[] = [];
    const request = store.openCursor();
    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor) {
        const msg = cursor.value as StoredMessage;
        if (searchableMessageText(msg).toLowerCase().includes(lower)) {
          results.push(msg);
        }
        cursor.continue();
      }
    };
    tx.oncomplete = () => {
      results.sort((a, b) => b.timestamp - a.timestamp);
      resolve(results);
    };
    tx.onerror = () => reject(tx.error);
  });
}

export async function queueOutboxMessage(msg: OutboxMessage): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(OUTBOX_STORE, "readwrite");
    tx.objectStore(OUTBOX_STORE).put(msg);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getOutboxMessages(userId?: string): Promise<OutboxMessage[]> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(OUTBOX_STORE, "readonly");
    const request = tx.objectStore(OUTBOX_STORE).getAll();
    request.onsuccess = () => {
      const messages = request.result as OutboxMessage[];
      resolve(userId ? messages.filter((message) => message.userId === userId) : messages);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function removeOutboxMessage(id: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(OUTBOX_STORE, "readwrite");
    tx.objectStore(OUTBOX_STORE).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function clearOutboxMessages(userId?: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(OUTBOX_STORE, "readwrite");
    const store = tx.objectStore(OUTBOX_STORE);
    if (!userId) {
      store.clear();
    } else {
      const request = store.openCursor();
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor) {
          const message = cursor.value as OutboxMessage;
          if (message.userId === userId) {
            cursor.delete();
          }
          cursor.continue();
        }
      };
      request.onerror = () => reject(request.error);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function saveSessionCache(
  userId: string,
  peerId: string,
  sealedSession: string
): Promise<void> {
  const db = await open();
  const session: StoredSession = {
    id: `${userId}:${peerId}`,
    userId,
    peerId,
    sealedSession,
    updatedAt: Date.now(),
  };
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SESSIONS_STORE, "readwrite");
    tx.objectStore(SESSIONS_STORE).put(session);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadSessionCache(
  userId: string,
  peerId: string
): Promise<string | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SESSIONS_STORE, "readonly");
    const request = tx.objectStore(SESSIONS_STORE).get(`${userId}:${peerId}`);
    request.onsuccess = () => {
      const session = request.result as StoredSession | undefined;
      resolve(session?.sealedSession ?? null);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function clearSessionCache(
  userId: string,
  peerId: string
): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SESSIONS_STORE, "readwrite");
    tx.objectStore(SESSIONS_STORE).delete(`${userId}:${peerId}`);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function clearAllSessionCache(userId?: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SESSIONS_STORE, "readwrite");
    const store = tx.objectStore(SESSIONS_STORE);
    if (!userId) {
      store.clear();
    } else {
      const index = store.index("by_user");
      const request = index.openCursor(userId);
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        }
      };
      request.onerror = () => reject(request.error);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function saveMetadataRecord(id: string, rawJson: string): Promise<void> {
  const db = await open();
  const record: StoredMetadata = {
    id,
    rawJson,
    updatedAt: Date.now(),
  };
  return new Promise((resolve, reject) => {
    const tx = db.transaction(METADATA_STORE, "readwrite");
    tx.objectStore(METADATA_STORE).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadMetadataRecord(id: string): Promise<string | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(METADATA_STORE, "readonly");
    const request = tx.objectStore(METADATA_STORE).get(id);
    request.onsuccess = () => {
      const record = request.result as StoredMetadata | undefined;
      resolve(record?.rawJson ?? null);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function clearMetadataRecord(id: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(METADATA_STORE, "readwrite");
    tx.objectStore(METADATA_STORE).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function saveKeyRecord(id: string, sealedKeys: string): Promise<void> {
  const db = await open();
  const record: StoredKeyRecord = {
    id,
    sealedKeys,
    updatedAt: Date.now(),
  };
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEYS_STORE, "readwrite");
    tx.objectStore(KEYS_STORE).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadKeyRecord(id: string): Promise<string | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEYS_STORE, "readonly");
    const request = tx.objectStore(KEYS_STORE).get(id);
    request.onsuccess = () => {
      const record = request.result as StoredKeyRecord | undefined;
      resolve(record?.sealedKeys ?? null);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function listKeyRecordIds(): Promise<string[]> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEYS_STORE, "readonly");
    const request = tx.objectStore(KEYS_STORE).getAllKeys();
    request.onsuccess = () => {
      resolve((request.result as IDBValidKey[]).map((value) => String(value)));
    };
    request.onerror = () => reject(request.error);
  });
}

export async function clearKeyRecord(id: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEYS_STORE, "readwrite");
    tx.objectStore(KEYS_STORE).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Add or toggle a reaction on a stored message. */
export async function addReaction(messageId: string, emoji: string, sender: string): Promise<StoredMessage | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readwrite");
    const store = tx.objectStore(MESSAGES_STORE);
    const req = store.get(messageId);
    req.onsuccess = () => {
      const msg = req.result as StoredMessage | undefined;
      if (!msg) { resolve(null); return; }
      const reactions = msg.reactions ?? [];
      const idx = reactions.findIndex(r => r.emoji === emoji && r.sender === sender);
      if (idx >= 0) reactions.splice(idx, 1); else reactions.push({ emoji, sender });
      msg.reactions = reactions;
      store.put(msg);
      tx.oncomplete = () => resolve(msg);
    };
    tx.onerror = () => reject(tx.error);
  });
}

/** Update the text of a stored message (for edits). */
export async function editStoredMessage(messageId: string, newText: string): Promise<StoredMessage | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readwrite");
    const store = tx.objectStore(MESSAGES_STORE);
    const req = store.get(messageId);
    req.onsuccess = () => {
      const msg = req.result as StoredMessage | undefined;
      if (!msg) { resolve(null); return; }
      msg.text = newText;
      if (msg.fileId || msg.attachmentDataBase64) {
        msg.attachmentNoteText = newText;
      }
      msg.editedAt = Date.now();
      store.put(msg);
      tx.oncomplete = () => resolve(msg);
    };
    tx.onerror = () => reject(tx.error);
  });
}

/** Get a single stored message by ID. */
export async function getMessage(id: string): Promise<StoredMessage | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(MESSAGES_STORE, "readonly");
    const req = tx.objectStore(MESSAGES_STORE).get(id);
    req.onsuccess = () => resolve((req.result as StoredMessage) ?? null);
    req.onerror = () => reject(req.error);
  });
}
