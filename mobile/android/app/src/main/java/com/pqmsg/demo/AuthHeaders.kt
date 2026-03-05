package com.pqmsg.demo

import uniffi.pqmsg_android.RequestAuthHeaders

fun RequestAuthHeaders.toHeaderMap(): Map<String, String> {
    return mapOf(
        "x-pqmsg-auth-user" to authUser,
        "x-pqmsg-auth-device" to authDevice,
        "x-pqmsg-auth-timestamp" to authTimestamp,
        "x-pqmsg-auth-nonce" to authNonce,
        "x-pqmsg-auth-signature" to authSignature,
    )
}
