package com.pqmsg.demo

import org.junit.Assert.assertEquals
import org.junit.Test

class MessagingCoordinatorTest {
    @Test
    fun parse_compose_target_normalizes_direct_usernames() {
        val target = MessagingCoordinator.parseComposeTarget(
            "  @TestUser  ",
            "http://10.0.2.2:3000",
        )

        assertEquals("TestUser", target.peerUserId)
        assertEquals("http://10.0.2.2:3000/", target.serverUrl)
    }

    @Test
    fun normalized_device_id_defaults_from_user() {
        val deviceId = MessagingCoordinator.normalizedDeviceId("alice", "")

        assertEquals("alice-android-1", deviceId)
    }

    @Test
    fun normalize_suite_label_defaults_to_ml_kem() {
        assertEquals("ml-kem-768", MessagingCoordinator.normalizeSuiteLabel("   "))
        assertEquals("kyber768", MessagingCoordinator.normalizeSuiteLabel("KYBER768"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parse_compose_target_rejects_blank_input() {
        MessagingCoordinator.parseComposeTarget(
            "   ",
            "http://10.0.2.2:3000",
        )
    }
}
