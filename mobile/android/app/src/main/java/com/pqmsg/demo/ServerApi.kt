package com.pqmsg.demo

import okhttp3.OkHttpClient
import okhttp3.CertificatePinner
import okhttp3.logging.HttpLoggingInterceptor
import okhttp3.HttpUrl.Companion.toHttpUrl
import retrofit2.Retrofit
import retrofit2.Response
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.HeaderMap
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

data class RegisterUserRequest(
    val user_id: String,
    val identity_x25519_pub: String,
    val identity_sig_pub: String,
    val device_id: String,
)

data class RegisterUserResponse(
    val user_id: String,
    val device_id: String,
    val registered_at: String,
)

data class PublishPrekeysRequest(
    val signed_prekey_x25519_pub: String,
    val sig_over_spk: String,
    val pq_signed_prekey_pub_mlkem768: String,
    val sig_over_pqspk: String,
    val one_time_prekeys_x25519: List<String>,
    val one_time_prekeys_mlkem768: List<String>,
)

data class PublishPrekeysResponse(
    val user_id: String,
    val device_id: String,
    val uploaded_one_time_prekeys_x25519: Int,
    val uploaded_one_time_prekeys_mlkem768: Int,
    val remaining_one_time_prekeys_x25519: Int,
    val remaining_one_time_prekeys_mlkem768: Int,
    val low_one_time_prekeys: Boolean,
    val minimum_recommended_one_time_prekeys: Int,
    val updated_at: String,
)

data class PrekeysStatusResponse(
    val user_id: String,
    val device_id: String,
    val remaining_one_time_prekeys_x25519: Int,
    val remaining_one_time_prekeys_mlkem768: Int,
    val low_one_time_prekeys: Boolean,
    val minimum_recommended_one_time_prekeys: Int,
    val checked_at: String,
)

data class RegisterPushTokenRequest(
    val device_id: String,
    val fcm_token: String,
)

data class RegisterPushTokenResponse(
    val user_id: String,
    val device_id: String,
    val provider: String,
    val registered_at: String,
)

data class BundleResponse(
    val user_id: String,
    val device_id: String,
    val identity_x25519_pub: String,
    val identity_sig_pub: String,
    val signed_prekey_x25519_pub: String,
    val sig_over_spk: String,
    val pq_signed_prekey_pub_mlkem768: String,
    val sig_over_pqspk: String,
    val one_time_prekey_x25519: String?,
    val one_time_prekey_mlkem768: String?,
    val remaining_one_time_prekeys_x25519: Int?,
    val remaining_one_time_prekeys_mlkem768: Int?,
    val low_one_time_prekeys: Boolean?,
    val minimum_recommended_one_time_prekeys: Int?,
    val last_resort_prekey_only: Boolean?,
    val identity_key_version: Int?,
    val identity_fingerprint_sha256: String?,
    val bundle_generated_at: String,
)

data class RelayRequest(
    val sender_user_id: String,
    val device_id: String,
    val message_bytes_base64: String,
)

data class RelayResponse(
    val message_id: Long,
    val received_at: String,
)

data class InboxMessage(
    val message_id: Long,
    val sender_user_id: String,
    val message_bytes_base64: String,
    val received_at: String,
)

data class InboxResponse(
    val user_id: String,
    val messages: List<InboxMessage>,
)

interface PqmsgApi {
    @GET("/")
    suspend fun pingRoot(): Response<Unit>

    @POST("/v1/users/register")
    suspend fun registerUser(@Body request: RegisterUserRequest): RegisterUserResponse

    @POST("/v1/users/{user_id}/prekeys")
    suspend fun publishPrekeys(
        @Path("user_id") userId: String,
        @Body request: PublishPrekeysRequest,
    ): PublishPrekeysResponse

    @GET("/v1/users/{user_id}/prekeys/status")
    suspend fun prekeysStatus(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
    ): PrekeysStatusResponse

    @POST("/v1/users/{user_id}/push-token")
    suspend fun registerPushToken(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RegisterPushTokenRequest,
    ): RegisterPushTokenResponse

    @GET("/v1/users/{user_id}/bundle")
    suspend fun getBundle(@Path("user_id") userId: String): BundleResponse

    @POST("/v1/relay/{recipient_user_id}")
    suspend fun relay(
        @Path("recipient_user_id") recipientUserId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RelayRequest,
    ): RelayResponse

    @GET("/v1/inbox/{user_id}")
    suspend fun inbox(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Query("since") since: Long,
    ): InboxResponse
}

object ApiClientFactory {
    fun create(serverUrl: String): PqmsgApi {
        val policy = resolveTransportPolicy(
            serverUrl,
            BuildConfig.ALLOW_CLEARTEXT_DEMO,
            BuildConfig.TLS_PIN_SHA256,
        )
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }
        val baseUrl = policy.baseUrl.toHttpUrl()
        val clientBuilder = OkHttpClient.Builder()
            .addInterceptor(logging)
        val certificatePin = policy.certificatePin
        if (certificatePin != null) {
            clientBuilder.certificatePinner(
                CertificatePinner.Builder()
                    .add(baseUrl.host, certificatePin)
                    .build()
            )
        }
        val client = clientBuilder.build()
        return Retrofit.Builder()
            .baseUrl(policy.baseUrl)
            .addConverterFactory(GsonConverterFactory.create())
            .client(client)
            .build()
            .create(PqmsgApi::class.java)
    }

    data class TransportPolicy(
        val baseUrl: String,
        val certificatePin: String?,
    )

    internal fun resolveTransportPolicy(
        base: String,
        allowCleartextDemo: Boolean,
        tlsPinSha256: String,
    ): TransportPolicy {
        val normalized = normalizeBaseUrl(base)
        val url = normalized.toHttpUrl()
        return when (url.scheme) {
            "http" -> {
                require(allowCleartextDemo && isLocalDemoHost(url.host)) {
                    "HTTP transport is only allowed for local demo hosts in debug mode"
                }
                TransportPolicy(baseUrl = normalized, certificatePin = null)
            }

            "https" -> {
                val pin = tlsPinSha256.trim()
                require(pin.isNotBlank()) { "HTTPS requires BuildConfig.TLS_PIN_SHA256" }
                require(pin.startsWith("sha256/")) {
                    "TLS pin must start with 'sha256/'"
                }
                TransportPolicy(baseUrl = normalized, certificatePin = pin)
            }

            else -> error("unsupported URL scheme '${url.scheme}'")
        }
    }

    internal fun normalizeBaseUrl(base: String): String {
        val trimmed = base.trim()
        require(trimmed.isNotBlank()) { "server URL is empty" }
        val normalized = if (trimmed.endsWith("/")) trimmed else "$trimmed/"
        val url = normalized.toHttpUrl()
        require(url.scheme == "http" || url.scheme == "https") {
            "server URL must use http or https"
        }
        return normalized
    }

    internal fun isLocalDemoHost(host: String): Boolean {
        return host == "10.0.2.2" || host == "127.0.0.1" || host == "localhost"
    }
}
