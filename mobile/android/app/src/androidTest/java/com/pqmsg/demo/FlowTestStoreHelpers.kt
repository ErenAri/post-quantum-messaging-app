package com.pqmsg.demo

import android.content.Context
import uniffi.pqmsg_android.Suite
import uniffi.pqmsg_android.generateIdentityKeys

object FlowTestStoreHelpers {
    fun resetToBlankSetup(context: Context) {
        val store = LocalStateStore(context)
        store.saveSetup(
            SetupConfig(
                serverUrl = "http://10.0.2.2:3000",
                userId = "",
                deviceId = "",
                suiteLabel = "ml-kem-768",
                peerUserId = "bob",
            ),
        )
    }

    fun seedSecureProfile(
        context: Context,
        userId: String,
        peerUserId: String = "test2",
    ): LocalStateStore {
        val store = LocalStateStore(context)
        store.wipeUserState(userId)
        val keysJson = generateIdentityKeys(
            userId,
            "${userId}-device",
            Suite.ML_KEM768,
            16u,
        )
        store.writeKeys(userId, keysJson)
        store.saveSetup(
            SetupConfig(
                serverUrl = "http://127.0.0.1:1",
                userId = userId,
                deviceId = "${userId}-device",
                suiteLabel = "ml-kem-768",
                peerUserId = peerUserId,
            ),
        )
        return store
    }
}
