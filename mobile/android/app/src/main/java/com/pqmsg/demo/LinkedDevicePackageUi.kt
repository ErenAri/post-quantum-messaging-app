package com.pqmsg.demo

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import uniffi.pqmsg_android.SecondaryDeviceOnboardingPackage
import uniffi.pqmsg_android.Suite

const val LINKED_DEVICE_PACKAGE_CLIPBOARD_CLEAR_DELAY_SECONDS = 60

private val PACKAGE_TIME_FORMATTER: DateTimeFormatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME

fun formatLinkedDevicePackageExportedAt(unixSeconds: Long): String {
    return PACKAGE_TIME_FORMATTER.format(Instant.ofEpochSecond(unixSeconds).atOffset(ZoneOffset.UTC))
}

fun formatLinkedDevicePackagePreview(pkg: SecondaryDeviceOnboardingPackage): String {
    val suiteLabel = if (pkg.suite == Suite.KYBER768) "kyber768" else "ml-kem-768"
    return buildString {
        append("Linked device package preview\n")
        append("User: ${pkg.userId}\n")
        append("Device: ${pkg.deviceId}\n")
        append("Server: ${pkg.serverUrl}\n")
        append("Suite: $suiteLabel\n")
        append("Exported: ${formatLinkedDevicePackageExportedAt(pkg.exportedAtUnix.toLong())}")
    }
}

fun buildLinkedDeviceImportWarnings(
    currentServerUrl: String,
    currentUserId: String,
    currentDeviceId: String,
    hasExistingLocalStateForImportedUser: Boolean,
    pkg: SecondaryDeviceOnboardingPackage,
): List<String> {
    val warnings = mutableListOf<String>()
    val normalizedServer = currentServerUrl.trim()
    val normalizedUser = currentUserId.trim()
    val normalizedDevice = currentDeviceId.trim()

    if (normalizedServer.isNotBlank() && normalizedServer != pkg.serverUrl) {
        warnings += "The package server overrides the currently typed server."
    }
    if (normalizedUser.isNotBlank() && normalizedUser != pkg.userId) {
        warnings += "The package user overrides the currently typed username."
    }
    if (normalizedDevice.isNotBlank() && normalizedDevice != pkg.deviceId) {
        warnings += "The package device overrides the currently typed device id."
    }
    if (hasExistingLocalStateForImportedUser) {
        warnings += "Existing local secure state for ${pkg.userId} will be replaced on this device."
    }
    return warnings
}

fun buildLinkedDeviceImportConfirmationMessage(
    pkg: SecondaryDeviceOnboardingPackage,
    warnings: List<String>,
): String {
    return buildString {
        append(formatLinkedDevicePackagePreview(pkg))
        if (warnings.isNotEmpty()) {
            append("\n\nWarnings:\n")
            append(warnings.joinToString("\n") { "- $it" })
        }
        append("\n\nContinue importing this linked-device package?")
    }
}
