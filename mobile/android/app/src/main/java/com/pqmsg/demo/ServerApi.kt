package com.pqmsg.demo

import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
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
    val updated_at: String,
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
    @POST("/v1/users/register")
    suspend fun registerUser(@Body request: RegisterUserRequest): RegisterUserResponse

    @POST("/v1/users/{user_id}/prekeys")
    suspend fun publishPrekeys(
        @Path("user_id") userId: String,
        @Body request: PublishPrekeysRequest,
    ): PublishPrekeysResponse

    @GET("/v1/users/{user_id}/bundle")
    suspend fun getBundle(@Path("user_id") userId: String): BundleResponse

    @POST("/v1/relay/{recipient_user_id}")
    suspend fun relay(
        @Path("recipient_user_id") recipientUserId: String,
        @Body request: RelayRequest,
    ): RelayResponse

    @GET("/v1/inbox/{user_id}")
    suspend fun inbox(
        @Path("user_id") userId: String,
        @Query("since") since: Long,
    ): InboxResponse
}

object ApiClientFactory {
    fun create(serverUrl: String): PqmsgApi {
        val normalized = normalizeBaseUrl(serverUrl)
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }
        val client = OkHttpClient.Builder()
            .addInterceptor(logging)
            .build()
        return Retrofit.Builder()
            .baseUrl(normalized)
            .addConverterFactory(GsonConverterFactory.create())
            .client(client)
            .build()
            .create(PqmsgApi::class.java)
    }

    private fun normalizeBaseUrl(base: String): String {
        val trimmed = base.trim()
        require(trimmed.isNotBlank()) { "server URL is empty" }
        return if (trimmed.endsWith("/")) trimmed else "$trimmed/"
    }
}
