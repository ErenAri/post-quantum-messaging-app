package com.pqmsg.demo

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertNull
import org.junit.Test

class ServerApiTest {
    private val gson = Gson()

    @Test
    fun normalize_base_url_trims_and_adds_trailing_slash() {
        val normalized = ApiClientFactory.normalizeBaseUrl(" http://10.0.2.2:3000 ")
        assertEquals("http://10.0.2.2:3000/", normalized)
    }

    @Test
    fun normalize_base_url_preserves_existing_trailing_slash() {
        val normalized = ApiClientFactory.normalizeBaseUrl("http://localhost:3000/")
        assertEquals("http://localhost:3000/", normalized)
    }

    @Test
    fun normalize_base_url_rejects_blank() {
        assertThrows(IllegalArgumentException::class.java) {
            ApiClientFactory.normalizeBaseUrl("   ")
        }
    }

    @Test
    fun resolve_transport_policy_allows_local_http_for_demo() {
        val policy = ApiClientFactory.resolveTransportPolicy(
            "http://10.0.2.2:3000",
            allowCleartextDemo = true,
            tlsPinSha256 = "",
        )
        assertEquals("http://10.0.2.2:3000/", policy.baseUrl)
        assertNull(policy.certificatePin)
    }

    @Test
    fun resolve_transport_policy_rejects_remote_http() {
        assertThrows(IllegalArgumentException::class.java) {
            ApiClientFactory.resolveTransportPolicy(
                "http://example.com",
                allowCleartextDemo = true,
                tlsPinSha256 = "",
            )
        }
    }

    @Test
    fun resolve_transport_policy_requires_pin_for_https() {
        assertThrows(IllegalArgumentException::class.java) {
            ApiClientFactory.resolveTransportPolicy(
                "https://example.com",
                allowCleartextDemo = false,
                tlsPinSha256 = "",
            )
        }
        val policy = ApiClientFactory.resolveTransportPolicy(
            "https://example.com",
            allowCleartextDemo = false,
            tlsPinSha256 = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        assertEquals(
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            policy.certificatePin
        )
    }

    @Test
    fun capabilities_response_parses_web_client_policy() {
        val parsed = gson.fromJson(
            """
            {
              "capability_schema_version": 1,
              "security_profile": "research",
              "deployment_mode": "demo",
              "tls_required": false,
              "tls_enabled": false,
              "supported_suite_ids": [42],
              "runtime_crypto_profile": {
                "protocol_version": 1,
                "suite_id": 42,
                "kem": "ml-kem-768",
                "dh": "x25519",
                "kdf": "hkdf-sha256",
                "aead": "chacha20-poly1305",
                "signature": "ed25519",
                "pq_oqs_enabled": true,
                "fips_mode": false
              },
              "production_baseline_met": false,
              "registration_pow_bits": 0,
              "prekey_bundle_reserve_count": 10,
              "pq_ratchet_interval": 1,
              "contact_discovery_supported": false,
              "presence_supported": false,
              "typing_indicators_supported": false,
              "read_receipts_supported": false,
              "calling_supported": false,
              "stories_supported": false,
              "channels_supported": false,
              "group_messaging_supported": false,
              "sealed_sender_required": true,
              "sender_certificate_supported": true,
              "key_transparency_supported": true,
              "sealed_delivery_tokens_supported": true,
              "sender_certificate_issuer_ed25519_pub": "issuer-ed25519-pub",
              "transparency_log_issuer_ed25519_pub": "issuer-ed25519-pub",
              "authenticated_direct_messaging_supported": false,
              "ephemeral_messaging_supported": false,
              "web_client_policy": "demo_only"
            }
            """.trimIndent(),
            ServerCapabilitiesResponse::class.java,
        )

        assertEquals("demo_only", parsed.web_client_policy)
        assertEquals("ml-kem-768", parsed.runtime_crypto_profile.kem)
        assertEquals(false, parsed.presence_supported)
        assertEquals(false, parsed.typing_indicators_supported)
        assertEquals(false, parsed.read_receipts_supported)
        assertEquals(false, parsed.calling_supported)
        assertEquals(false, parsed.stories_supported)
        assertEquals(false, parsed.channels_supported)
        assertEquals(false, parsed.group_messaging_supported)
        assertEquals(true, parsed.sealed_sender_required)
        assertEquals(true, parsed.sender_certificate_supported)
        assertEquals(true, parsed.key_transparency_supported)
        assertEquals(true, parsed.sealed_delivery_tokens_supported)
        assertEquals("issuer-ed25519-pub", parsed.sender_certificate_issuer_ed25519_pub)
        assertEquals("issuer-ed25519-pub", parsed.transparency_log_issuer_ed25519_pub)
        assertEquals(false, parsed.authenticated_direct_messaging_supported)
        assertEquals(false, parsed.ephemeral_messaging_supported)
    }

    @Test
    fun validate_capabilities_requires_per_message_pq_ratchet() {
        val parsed = gson.fromJson(
            """
            {
              "capability_schema_version": 1,
              "security_profile": "research",
              "deployment_mode": "development",
              "tls_required": false,
              "tls_enabled": false,
              "supported_suite_ids": [1],
              "runtime_crypto_profile": {
                "protocol_version": 1,
                "suite_id": 1,
                "kem": "ml-kem-768",
                "dh": "x25519",
                "kdf": "hkdf-sha256",
                "aead": "chacha20-poly1305",
                "signature": "ed25519",
                "pq_oqs_enabled": true,
                "fips_mode": false
              },
              "production_baseline_met": false,
              "registration_pow_bits": 0,
              "prekey_bundle_reserve_count": 10,
              "pq_ratchet_interval": 5,
              "contact_discovery_supported": false,
              "presence_supported": false,
              "typing_indicators_supported": false,
              "read_receipts_supported": false,
              "calling_supported": false,
              "stories_supported": false,
              "channels_supported": false,
              "group_messaging_supported": false,
              "sealed_sender_required": true,
              "sender_certificate_supported": true,
              "key_transparency_supported": true,
              "sealed_delivery_tokens_supported": true,
              "sender_certificate_issuer_ed25519_pub": "issuer-ed25519-pub",
              "transparency_log_issuer_ed25519_pub": "issuer-ed25519-pub",
              "authenticated_direct_messaging_supported": false,
              "ephemeral_messaging_supported": false,
              "web_client_policy": "demo_only"
            }
            """.trimIndent(),
            ServerCapabilitiesResponse::class.java,
        )

        assertThrows(IllegalArgumentException::class.java) {
            ApiClientFactory.validateCapabilities(parsed, "ml-kem-768")
        }
    }

    @Test
    fun poll_call_signals_response_parses_signal_id() {
        val parsed = gson.fromJson(
            """
            {
              "call_id": "call-123",
              "signals": [
                {
                  "signal_id": 17,
                  "signal_type": "answer",
                  "from_user_id": "bob",
                  "payload_base64": "c2Rw",
                  "created_at": "2026-03-09T10:00:00Z"
                }
              ]
            }
            """.trimIndent(),
            PollCallSignalsResponse::class.java,
        )

        assertEquals("call-123", parsed.call_id)
        assertEquals(1, parsed.signals.size)
        assertEquals(17L, parsed.signals.first().signal_id)
    }

    @Test
    fun group_relay_request_serializes_per_recipient_payloads() {
        val json = gson.toJson(
            GroupRelayRequest(
                sender_user_id = "alice",
                device_id = "device-a",
                recipients = listOf(
                    GroupRelayRecipient(
                        recipient_user_id = "bob",
                        message_bytes_base64 = "Ym9iLW1zZw==",
                    ),
                    GroupRelayRecipient(
                        recipient_user_id = "carol",
                        message_bytes_base64 = "Y2Fyb2wtbXNn",
                    ),
                ),
            )
        )

        val parsed = gson.fromJson(json, GroupRelayRequest::class.java)
        assertEquals("alice", parsed.sender_user_id)
        assertEquals("device-a", parsed.device_id)
        assertEquals(2, parsed.recipients.size)
        assertEquals("bob", parsed.recipients[0].recipient_user_id)
        assertEquals("Ym9iLW1zZw==", parsed.recipients[0].message_bytes_base64)
        assertEquals("carol", parsed.recipients[1].recipient_user_id)
    }
}
