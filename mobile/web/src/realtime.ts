/**
 * WebSocket real-time inbox delivery.
 * Connects to /v1/ws/inbox/:user_id with auth headers as query params.
 */

import type { GeneratedKeys } from "./crypto";
import { buildInboxAuthHeaders } from "./crypto";
import { readCursor } from "./storage";

export type WsInboxMessage = {
  message_id: number;
  sender_user_id: string;
  message_bytes_base64: string;
  received_at: string;
};

type WsListener = (msg: WsInboxMessage) => void;

export class RealtimeInbox {
  private ws: WebSocket | null = null;
  private listeners: WsListener[] = [];
  private reconnectListeners: Array<() => void> = [];
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionallyClosed = false;
  private serverUrl: string;
  private keys: GeneratedKeys;

  constructor(serverUrl: string, keys: GeneratedKeys) {
    this.serverUrl = serverUrl;
    this.keys = keys;
  }

  onMessage(listener: WsListener): void {
    this.listeners.push(listener);
  }

  onReconnect(listener: () => void): void {
    this.reconnectListeners.push(listener);
  }

  connect(): void {
    this.intentionallyClosed = false;
    this.doConnect();
  }

  disconnect(): void {
    this.intentionallyClosed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  private doConnect(): void {
    if (this.intentionallyClosed) return;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    const since = readCursor(this.keys.userId);
    const headers = buildInboxAuthHeaders(this.keys, since);

    // Build WebSocket URL with auth as query params
    const base = this.serverUrl.replace(/^http/, "ws");
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(headers)) {
      params.set(k, v);
    }
    params.set("since", String(since));
    const url = `${base}/v1/ws/inbox/${encodeURIComponent(this.keys.userId)}?${params.toString()}`;

    const ws = new WebSocket(url);

    ws.onopen = () => {
      console.log("[ws] connected");
      for (const listener of this.reconnectListeners) {
        listener();
      }
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(String(event.data)) as WsInboxMessage;
        for (const listener of this.listeners) {
          listener(msg);
        }
      } catch (e) {
        console.warn("[ws] failed to parse message", e);
      }
    };

    ws.onclose = () => {
      console.log("[ws] disconnected");
      this.ws = null;
      if (!this.intentionallyClosed) {
        this.scheduleReconnect();
      }
    };

    ws.onerror = () => {
      // onclose will fire after onerror
    };

    this.ws = ws;
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.doConnect();
    }, 3000);
  }
}
