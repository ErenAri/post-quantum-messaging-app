/**
 * WebSocket real-time inbox delivery.
 * Fetches a short-lived ticket, then connects to the sealed inbox websocket
 * path used by the supported web messaging profile.
 */

import type { GeneratedKeys } from "./crypto";
import { buildSealedInboxAuthHeaders } from "./crypto";
import { PqmsgApi } from "./server";
import { readSealedCursor } from "./storage";

export type WsInboxMessage = {
  message_id: number;
  sender_user_id?: string;
  sender_identity_x25519_pub?: string;
  message_bytes_base64: string;
  received_at: string;
};

type WsInboxEnvelope = {
  event: "sync" | "relay";
  user_id: string;
  messages: WsInboxMessage[];
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
    void this.doConnect();
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

  private async doConnect(): Promise<void> {
    if (this.intentionallyClosed) return;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    const since = readSealedCursor(this.keys.userId, this.keys.deviceId);
    const headers = buildSealedInboxAuthHeaders(this.keys, since);
    const api = new PqmsgApi(this.serverUrl);
    let ticket: string;
    try {
      const issued = await api.createSealedInboxWsTicket(this.keys.userId, since, headers);
      ticket = issued.ticket;
    } catch (error) {
      console.warn("[ws] failed to create inbox ticket", error);
      this.scheduleReconnect();
      return;
    }

    const base = this.serverUrl.replace(/^http/, "ws");
    const url =
      `${base}/v1/ws/sealed-inbox/${encodeURIComponent(this.keys.userId)}` +
      `?ticket=${encodeURIComponent(ticket)}`;

    const ws = new WebSocket(url);

    ws.onopen = () => {
      console.log("[ws] connected");
      for (const listener of this.reconnectListeners) {
        listener();
      }
    };

    ws.onmessage = (event) => {
      try {
        const envelope = JSON.parse(String(event.data)) as WsInboxEnvelope;
        for (const msg of envelope.messages ?? []) {
          for (const listener of this.listeners) {
            listener(msg);
          }
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
      void this.doConnect();
    }, 3000);
  }
}
