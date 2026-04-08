package com.pqmsg.demo

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class PrivacyPolicyActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_privacy_policy)

        findViewById<Button>(R.id.buttonBackPrivacyPolicy).setOnClickListener { finish() }
        findViewById<Button>(R.id.buttonOpenPublicPrivacyPolicy).setOnClickListener {
            openExternalUrl(getString(R.string.privacy_policy_public_url))
        }
        findViewById<Button>(R.id.buttonOpenAccountDeletionHelp).setOnClickListener {
            openExternalUrl(getString(R.string.account_deletion_public_url))
        }

        val body = findViewById<TextView>(R.id.textPrivacyPolicyBody)
        body.text = runCatching {
            resources.openRawResource(R.raw.privacy_policy)
                .bufferedReader()
                .use { it.readText() }
        }.getOrElse {
            getString(R.string.privacy_policy_load_failed)
        }
    }

    private fun openExternalUrl(url: String) {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }
}
