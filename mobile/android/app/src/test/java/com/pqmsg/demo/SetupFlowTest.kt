package com.pqmsg.demo

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SetupFlowTest {
    @Test
    fun flow_requires_ordered_steps() {
        var progress = SetupProgress()
        assertFalse(progress.canRegister())
        assertFalse(progress.canPublishPrekeys())
        assertFalse(progress.canVerifyServer())
        assertFalse(progress.canOpenChat("bob"))

        progress = progress.afterKeysGenerated()
        assertTrue(progress.canRegister())
        assertFalse(progress.canPublishPrekeys())
        assertFalse(progress.canVerifyServer())

        progress = progress.afterUserRegistered()
        assertTrue(progress.canPublishPrekeys())
        assertFalse(progress.canVerifyServer())

        progress = progress.afterPrekeysPublished()
        assertTrue(progress.canVerifyServer())
        assertFalse(progress.canOpenChat("bob"))

        progress = progress.afterServerVerified()
        assertTrue(progress.canOpenChat("bob"))
        assertFalse(progress.canOpenChat(""))
    }

    @Test
    fun regenerating_keys_resets_downstream_steps() {
        val progress = SetupProgress(
            keysGenerated = true,
            userRegistered = true,
            prekeysPublished = true,
            serverVerified = true,
        ).afterKeysGenerated()
        assertTrue(progress.keysGenerated)
        assertFalse(progress.userRegistered)
        assertFalse(progress.prekeysPublished)
        assertFalse(progress.serverVerified)
    }
}
