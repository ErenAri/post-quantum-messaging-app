package com.pqmsg.demo

import retrofit2.HttpException
import uniffi.pqmsg_android.PqmsgAndroidException
import java.io.IOException

data class UiError(
    val headline: String,
    val actionHint: String,
    val technicalDetails: String,
)

object UiErrorMapper {
    fun fromThrowable(error: Throwable, action: String): UiError {
        val message = error.message ?: "no message"
        val details = "${error::class.java.simpleName}: $message"
        return when (error) {
            is LocalSecureStorageUnavailableException -> UiError(
                headline = "Local secure storage is unavailable on this device",
                actionHint = "Re-import a linked-device package or fully reprovision this device. Cloud backup restore is intentionally disabled for this state.",
                technicalDetails = details,
            )

            is PqmsgAndroidException.InvalidInput -> {
                if (message.contains("onboarding package", ignoreCase = true)) {
                    UiError(
                        headline = "$action failed due to linked-device package validation",
                        actionHint = "Verify the package preview, passphrase, and trusted source before retrying the import.",
                        technicalDetails = details,
                    )
                } else {
                    UiError(
                        headline = "$action failed due to invalid input",
                        actionHint = "Check user, device, suite, and peer values, then retry.",
                        technicalDetails = details,
                    )
                }
            }

            is PqmsgAndroidException.OperationFailed -> UiError(
                headline = "$action failed in cryptographic operation",
                actionHint = "Retry once; if it repeats, regenerate keys for this user.",
                technicalDetails = details,
            )

            is IllegalStateException -> {
                if (message.contains("identity key changed", ignoreCase = true)) {
                    UiError(
                        headline = "Peer identity key changed",
                        actionHint = "Verify peer fingerprint out-of-band before trusting key update.",
                        technicalDetails = details,
                    )
                } else {
                    UiError(
                        headline = "$action failed",
                        actionHint = "Retry and inspect technical details if failure persists.",
                        technicalDetails = details,
                    )
                }
            }

            is HttpException -> UiError(
                headline = "$action failed: server returned ${error.code()}",
                actionHint = "Confirm server is running and endpoint inputs are correct.",
                technicalDetails = details,
            )

            is IOException -> UiError(
                headline = "$action failed: network unreachable",
                actionHint = "Use emulator URL http://10.0.2.2:3000 and ensure server is listening.",
                technicalDetails = details,
            )

            else -> UiError(
                headline = "$action failed",
                actionHint = "Retry and inspect technical details if failure persists.",
                technicalDetails = details,
            )
        }
    }
}
