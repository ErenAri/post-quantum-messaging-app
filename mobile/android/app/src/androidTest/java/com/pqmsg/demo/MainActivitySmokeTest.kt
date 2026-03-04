package com.pqmsg.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.widget.TextView
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivitySmokeTest {
    @Test
    fun launch_setup_screen() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity {
            assertNotNull(it.findViewById<TextView>(R.id.textStatusSetup))
        }
        scenario.close()
    }
}
