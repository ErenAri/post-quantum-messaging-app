import { describe, expect, it } from "vitest";
import { getWebBetaHoldback, WEB_BETA_SCOPE_SUMMARY } from "./betaScope";

describe("betaScope", () => {
  it("blocks outbound group messaging when capabilities are unavailable", () => {
    const holdback = getWebBetaHoldback(null);
    expect(holdback.messagingAllowed).toBe(false);
    expect(holdback.title).toContain("group");
    expect(holdback.detail).toContain("could not be verified");
  });

  it("blocks outbound group messaging when server policy is demo_only", () => {
    const holdback = getWebBetaHoldback({
      capability_schema_version: 1,
      security_profile: "research",
      deployment_mode: "demo",
      tls_required: false,
      tls_enabled: false,
      supported_suite_ids: [1],
      runtime_crypto_profile: {
        protocol_version: 1,
        suite_id: 1,
        kem: "ML-KEM-768",
        dh: "X25519",
        kdf: "HKDF-SHA256",
        aead: "ChaCha20-Poly1305",
        signature: "Ed25519",
        pq_oqs_enabled: true,
        fips_mode: false,
      },
      production_baseline_met: false,
      registration_pow_bits: 0,
      prekey_bundle_reserve_count: 8,
      pq_ratchet_interval: 1,
      contact_discovery_supported: false,
      presence_supported: false,
      typing_indicators_supported: false,
      read_receipts_supported: false,
      calling_supported: false,
      stories_supported: false,
      channels_supported: false,
      group_messaging_supported: false,
      sealed_sender_required: true,
      sealed_delivery_tokens_supported: true,
      authenticated_direct_messaging_supported: false,
      ephemeral_messaging_supported: false,
      web_client_policy: "demo_only",
    });
    expect(holdback.messagingAllowed).toBe(false);
    expect(holdback.detail).toContain("demo_only");
    expect(holdback.detail).toContain("private group design");
  });

  it("still blocks group messaging when server policy looks interoperable", () => {
    const holdback = getWebBetaHoldback({
      capability_schema_version: 1,
      security_profile: "research",
      deployment_mode: "demo",
      tls_required: false,
      tls_enabled: false,
      supported_suite_ids: [1],
      runtime_crypto_profile: {
        protocol_version: 1,
        suite_id: 1,
        kem: "ML-KEM-768",
        dh: "X25519",
        kdf: "HKDF-SHA256",
        aead: "ChaCha20-Poly1305",
        signature: "Ed25519",
        pq_oqs_enabled: true,
        fips_mode: false,
      },
      production_baseline_met: false,
      registration_pow_bits: 0,
      prekey_bundle_reserve_count: 8,
      pq_ratchet_interval: 1,
      contact_discovery_supported: false,
      presence_supported: false,
      typing_indicators_supported: false,
      read_receipts_supported: false,
      calling_supported: false,
      stories_supported: false,
      channels_supported: false,
      group_messaging_supported: false,
      sealed_sender_required: true,
      sealed_delivery_tokens_supported: true,
      authenticated_direct_messaging_supported: false,
      ephemeral_messaging_supported: false,
      web_client_policy: "interop_candidate",
    });
    expect(holdback.messagingAllowed).toBe(false);
    expect(holdback.title).toContain("group messaging unavailable");
    expect(holdback.detail).toContain("interop_candidate");
    expect(holdback.detail).toContain("private group design");
  });

  it("exposes the shared scope summary", () => {
    expect(WEB_BETA_SCOPE_SUMMARY).toContain("direct messages");
    expect(WEB_BETA_SCOPE_SUMMARY).toContain("calling");
  });
});
