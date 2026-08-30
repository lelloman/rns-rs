package com.lelloman.rntun.service

import android.content.Context
import java.io.File
import java.time.Instant

object Diagnostics {
    private const val MAX_BYTES = 256 * 1024
    private val destination = Regex("(?i)\\b[0-9a-f]{32}\\b")
    private val ipv4 = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")

    @Synchronized
    fun record(context: Context, level: String, message: String) {
        val directory = File(context.filesDir, "rntun").apply { mkdirs() }
        val file = File(directory, "diagnostics.log")
        if (file.length() > MAX_BYTES) {
            File(directory, "diagnostics.previous.log").delete()
            file.renameTo(File(directory, "diagnostics.previous.log"))
        }
        val redacted = message
            .replace(destination, "<destination>")
            .replace(ipv4, "<ipv4>")
            .replace(Regex("(?i)(password|private[_ -]?key)\\s*[:=]\\s*\\S+"), "$1=<redacted>")
        file.appendText("${Instant.now()} $level ${redacted.take(1000)}\n")
    }

    fun read(context: Context): String =
        File(context.filesDir, "rntun/diagnostics.log").takeIf(File::exists)?.readText().orEmpty()

    fun clear(context: Context) {
        File(context.filesDir, "rntun/diagnostics.log").delete()
        File(context.filesDir, "rntun/diagnostics.previous.log").delete()
    }
}
