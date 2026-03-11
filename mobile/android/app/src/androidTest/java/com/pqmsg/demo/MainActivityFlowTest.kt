package com.pqmsg.demo

import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityFlowTest {
    @Test
    fun preset_alice_prefills_profile_inputs_and_summary() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        FlowTestStoreHelpers.resetToBlankSetup(context)

        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { activity ->
            activity.findViewById<com.google.android.material.button.MaterialButton>(R.id.buttonPresetAlice)
                .performClick()

            val userInput = activity.findViewById<EditText>(R.id.editUser)
            val deviceInput = activity.findViewById<EditText>(R.id.editDevice)
            val summary = activity.findViewById<TextView>(R.id.textSetupSummary)

            assertEquals("alice", userInput.text.toString())
            assertTrue(deviceInput.text.toString().startsWith("alice"))
            assertTrue(summary.text.toString().contains("alice"))
        }
        scenario.close()
    }
}
