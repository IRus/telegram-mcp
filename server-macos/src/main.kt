@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

import io.heapy.telegrammcp.*
import io.ktor.client.*
import io.ktor.client.engine.darwin.Darwin
import io.ktor.client.plugins.*
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import kotlinx.cinterop.toKString
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.buffered
import kotlinx.io.readString
import platform.posix.getenv

fun main() {
    val config = Config.load({ getenv(it)?.toKString() }, { SystemFileSystem.source(Path(it)).buffered().use { source -> source.readString() } })
    val client = HttpClient(Darwin) {
        followRedirects = false
        install(HttpTimeout) { requestTimeoutMillis = 120_000; connectTimeoutMillis = 10_000; socketTimeoutMillis = 30_000 }
    }
    try {
        embeddedServer(CIO, host = "0.0.0.0", port = 8080) { telegramMcp(config, client) }.start(wait = true)
    } finally { client.close() }
}
