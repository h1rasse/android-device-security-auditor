package com.h1rasse.securityauditor

import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.util.concurrent.Executors
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var reportView: TextView
    private val executor = Executors.newSingleThreadExecutor()

    private external fun nativeAudit(): String

    companion object {
        init { System.loadLibrary("security_auditor") }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(createContent())
        runAudit()
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun createContent(): ScrollView {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 40, 40, 40)
        }
        val title = TextView(this).apply {
            text = "Android Device Security Auditor"
            textSize = 22f
        }
        reportView = TextView(this).apply {
            text = "Preparing read-only audit..."
            textSize = 14f
            setPadding(0, 28, 0, 28)
        }
        val refreshButton = Button(this).apply {
            text = "Run audit again"
            setOnClickListener { runAudit() }
        }
        container.addView(title)
        container.addView(reportView)
        container.addView(refreshButton)
        return ScrollView(this).apply { addView(container) }
    }

    private fun runAudit() {
        reportView.text = "Running read-only security checks..."
        executor.execute {
            val report = buildReport()
            runOnUiThread { reportView.text = report.toString(2) }
        }
    }

    private fun buildReport(): JSONObject {
        val nativeReport = try { JSONObject(nativeAudit()) } catch (_: Exception) {
            JSONObject().put("nativeCheck", false)
        }
        val applicationFlags = applicationInfo.flags
        val report = JSONObject()
        report.put("timestampEpochMillis", System.currentTimeMillis())
        report.put("device", JSONObject().apply {
            put("manufacturer", Build.MANUFACTURER)
            put("brand", Build.BRAND)
            put("model", Build.MODEL)
            put("device", Build.DEVICE)
            put("androidVersion", Build.VERSION.RELEASE)
            put("sdkInt", Build.VERSION.SDK_INT)
            put("securityPatch", Build.VERSION.SECURITY_PATCH)
            put("abis", Build.SUPPORTED_ABIS.joinToString(","))
        })
        report.put("security", JSONObject().apply {
            put("rootIndicators", JSONObject().apply {
                put("testKeysBuild", Build.TAGS?.contains("test-keys") == true)
                put("suPathDetected", nativeReport.optBoolean("suPathDetected", false))
                put("systemWritable", nativeReport.optBoolean("systemWritable", false))
            })
            put("selinux", JSONObject().apply {
                put("enforceFile", nativeReport.optString("selinuxEnforceFile", "unknown"))
                put("status", readCommand("getenforce"))
            })
            put("verifiedBootState", readProperty("ro.boot.verifiedbootstate"))
            put("vbmetaDeviceState", readProperty("ro.boot.vbmeta.device_state"))
            put("bootloader", readProperty("ro.boot.flash.locked"))
            put("debuggableBuild", (applicationFlags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
            put("adbEnabled", Settings.Global.getInt(contentResolver, Settings.Global.ADB_ENABLED, 0) == 1)
            put("nativeCheck", nativeReport.optBoolean("nativeCheck", false))
            put("kernelTainted", nativeReport.optString("kernelTainted", "unknown"))
        })
        report.put("limitations", listOf(
            "These are local indicators, not a cryptographic attestation.",
            "No check can reliably prove that a device is safe or malware-free.",
            "Results vary by Android version, vendor, permissions, and device configuration."
        ).joinToString(" | "))
        return report
    }

    private fun readProperty(name: String): String = readCommand("getprop $name")

    private fun readCommand(command: String): String {
        return try {
            val process = Runtime.getRuntime().exec(command.split(" ").toTypedArray())
            process.inputStream.bufferedReader().use { it.readLine()?.trim().orEmpty() }.ifEmpty { "unknown" }
        } catch (_: Exception) { "unavailable" }
    }
}
