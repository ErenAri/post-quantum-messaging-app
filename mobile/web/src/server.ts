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

export type RetireCurrentDeviceResponse = {
  user_id: string;
  retired_device_id: string;
  retired_at: string;
  remaining_active_devices: number;
};

export type DeviceRecord = {
  device_id: string;
  active: boolean;
  linked_at: string;
  revoked_at: string | null;
};

export type DeviceListResponse = {
  user_id: string;
  devices: DeviceRecord[];
};

export type LinkDeviceResponse = {
  user_id: string;
  linked_device_id: string;
  linked_at: string;
};

export type RevokeDeviceResponse = {
  user_id: string;
  revoked_device_id: string;
  revoked_at: string;
};

export type RuntimeCryptoProfileResponse = {
  protocol_version: number;
  suite_id: number;
  kem: string;
  dh: string;
  kdf: string;
  aead: string;
  signature: string;
  pq_oqs_enabled: boolean;
  fips_mode: boolean;
};

export type ServerCapabilitiesResponse = {
  capability_schema_version: number;
  security_profile: string;
  deployment_mode: string;
  tls_required: boolean;
  tls_enabled: boolean;
  supported_suite_ids: number[];
  runtime_crypto_profile: RuntimeCryptoProfileResponse;
  production_baseline_met: boolean;
  registration_pow_bits: number;
  prekey_bundle_reserve_count: number;
  pq_ratchet_interval: number;
  web_client_policy: string;
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

  async getCapabilities(): Promise<ServerCapabilitiesResponse> {
    return this.request<ServerCapabilitiesResponse>("GET", "/v1/capabilities", undefined, {});
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

  async listDevices(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<DeviceListResponse> {
    return this.request<DeviceListResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/devices`,
      undefined,
      headers
    );
  }

  async linkDevice(
    userId: string,
    newDeviceId: string,
    headers: RequestAuthHeaders
  ): Promise<LinkDeviceResponse> {
    return this.request<LinkDeviceResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/devices/link`,
      { new_device_id: newDeviceId },
      headers
    );
  }

  async revokeDevice(
    userId: string,
    targetDeviceId: string,
    headers: RequestAuthHeaders
  ): Promise<RevokeDeviceResponse> {
    return this.request<RevokeDeviceResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/devices/${encodeURIComponent(targetDeviceId)}/revoke`,
      undefined,
      headers
    );
  }

  async retireCurrentDevice(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<RetireCurrentDeviceResponse> {
    return this.request<RetireCurrentDeviceResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/devices/current/retire`,
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
