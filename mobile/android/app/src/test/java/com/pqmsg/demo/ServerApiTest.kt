package com.pqmsg.demo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertNull
import org.junit.Test

class ServerApiTest {
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
}
