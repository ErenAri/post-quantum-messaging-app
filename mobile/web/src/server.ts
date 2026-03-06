import { RequestAuthHeaders } from "./crypto";

export type RegisterUserRequest = {
  user_id: string;
  identity_x25519_pub: string;
  identity_sig_pub: string;
  device_id: string;
};

export type RegisterUserResponse = {
  user_id: string;
  device_id: string;
  registered_at: string;
};

export type PublishPrekeysRequest = {
  signed_prekey_x25519_pub: string;
  sig_over_spk: string;
  pq_signed_prekey_pub_mlkem768: string;
  sig_over_pqspk: string;
  one_time_prekeys_x25519: string[];
  one_time_prekeys_mlkem768: string[];
};

export type PublishPrekeysResponse = {
  user_id: string;
  device_id: string;
  uploaded_one_time_prekeys_x25519: number;
  uploaded_one_time_prekeys_mlkem768: number;
  remaining_one_time_prekeys_x25519: number;
  remaining_one_time_prekeys_mlkem768: number;
  low_one_time_prekeys: boolean;
  minimum_recommended_one_time_prekeys: number;
  updated_at: string;
};

export type BundleResponse = {
  user_id: string;
  device_id: string;
  identity_x25519_pub: string;
  identity_sig_pub: string;
  signed_prekey_x25519_pub: string;
  sig_over_spk: string;
  pq_signed_prekey_pub_mlkem768: string;
  sig_over_pqspk: string;
  one_time_prekey_x25519: string | null;
  one_time_prekey_mlkem768: string | null;
  identity_fingerprint_sha256: string | null;
  identity_key_version: number;
  bundle_generated_at: string;
};

export type RelayRequest = {
  sender_user_id: string;
  device_id: string;
  message_bytes_base64: string;
};

export type RelayResponse = {
  message_id: number;
  received_at: string;
};

export type InboxMessage = {
  message_id: number;
  sender_user_id: string;
  message_bytes_base64: string;
  received_at: string;
};

export type InboxResponse = {
  user_id: string;
  messages: InboxMessage[];
};

export class PqmsgApi {
  private readonly baseUrl: string;

  constructor(serverUrl: string) {
    const normalized = serverUrl.trim().replace(/\/+$/, "");
    if (!normalized) {
      throw new Error("server URL is empty");
    }
    this.baseUrl = normalized;
  }

  async pingRoot(): Promise<void> {
    await this.request<void>("GET", "/", undefined, {});
  }

  async registerUser(payload: RegisterUserRequest): Promise<RegisterUserResponse> {
    return this.request<RegisterUserResponse>("POST", "/v1/users/register", payload, {});
  }

  async publishPrekeys(
    userId: string,
    payload: PublishPrekeysRequest,
    headers: RequestAuthHeaders
  ): Promise<PublishPrekeysResponse> {
    return this.request<PublishPrekeysResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/prekeys`,
      payload,
      headers
    );
  }

  async getBundle(userId: string): Promise<BundleResponse> {
    return this.request<BundleResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/bundle`,
      undefined,
      {}
    );
  }

  async relay(
    recipientUserId: string,
    payload: RelayRequest,
    headers: RequestAuthHeaders
  ): Promise<RelayResponse> {
    return this.request<RelayResponse>(
      "POST",
      `/v1/relay/${encodeURIComponent(recipientUserId)}`,
      payload,
      headers
    );
  }

  async inbox(
    userId: string,
    since: number,
    headers: RequestAuthHeaders
  ): Promise<InboxResponse> {
    return this.request<InboxResponse>(
      "GET",
      `/v1/inbox/${encodeURIComponent(userId)}?since=${encodeURIComponent(String(since))}`,
      undefined,
      headers
    );
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body: unknown,
    headers: Record<string, string>
  ): Promise<T> {
    const endpoint = `${this.baseUrl}${path}`;
    const requestHeaders = new Headers(headers);
    requestHeaders.set("accept", "application/json");
    if (body !== undefined) {
      requestHeaders.set("content-type", "application/json");
    }
    const response = await fetch(endpoint, {
      method,
      headers: requestHeaders,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`HTTP ${response.status}: ${text}`);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }
}
