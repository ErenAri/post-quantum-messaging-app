package com.pqmsg.demo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.pqmsg_android.SecondaryDeviceOnboardingPackage
import uniffi.pqmsg_android.Suite

class LinkedDevicePackageUiTest {
    private fun samplePackage(): SecondaryDeviceOnboardingPackage {
        return SecondaryDeviceOnboardingPackage(
            "https://relay.example.test",
            "alice",
            "alice-android-2",
            Suite.ML_KEM768,
            1_772_928_000,
            "{}",
        )
    }

    @Test
    fun preview_includes_export_metadata() {
        val preview = formatLinkedDevicePackagePreview(samplePackage())

        assertTrue(preview.contains("User: alice"))
        assertTrue(preview.contains("Device: alice-android-2"))
        assertTrue(preview.contains("Server: https://relay.example.test"))
        assertTrue(preview.contains("Suite: ml-kem-768"))
        assertTrue(preview.contains("Exported: 2026-03-08T00:00:00Z"))
    }

    @Test
    fun import_warnings_cover_field_overrides_and_existing_state() {
        val warnings = buildLinkedDeviceImportWarnings(
            currentServerUrl = "https://different.example",
            currentUserId = "bob",
            currentDeviceId = "bob-android-9",
            hasExistingLocalStateForImportedUser = true,
            pkg = samplePackage(),
        )

        assertEquals(4, warnings.size)
        assertTrue(warnings.any { it.contains("server overrides") })
        assertTrue(warnings.any { it.contains("username") })
        assertTrue(warnings.any { it.contains("device id") })
        assertTrue(warnings.any { it.contains("Existing local secure state") })
    }
}
