package com.pqmsg.demo

data class SetupProgress(
    val keysGenerated: Boolean = false,
    val userRegistered: Boolean = false,
    val prekeysPublished: Boolean = false,
    val serverVerified: Boolean = false,
) {
    fun afterKeysGenerated(): SetupProgress {
        return copy(
            keysGenerated = true,
            userRegistered = false,
            prekeysPublished = false,
            serverVerified = false,
        )
    }

    fun afterUserRegistered(): SetupProgress {
        return copy(
            userRegistered = true,
            prekeysPublished = false,
            serverVerified = false,
        )
    }

    fun afterPrekeysPublished(): SetupProgress {
        return copy(
            prekeysPublished = true,
            serverVerified = false,
        )
    }

    fun afterServerVerified(): SetupProgress {
        return copy(serverVerified = true)
    }

    fun reset(): SetupProgress {
        return SetupProgress()
    }

    fun canRegister(): Boolean {
        return keysGenerated
    }

    fun canPublishPrekeys(): Boolean {
        return keysGenerated && userRegistered
    }

    fun canVerifyServer(): Boolean {
        return keysGenerated && userRegistered && prekeysPublished
    }

    fun canOpenChat(): Boolean {
        return keysGenerated && userRegistered && prekeysPublished && serverVerified
    }
}
