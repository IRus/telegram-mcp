package io.heapy.telegrammcp

import io.ktor.http.*
import kotlinx.serialization.json.Json

data class Config(
    val publicHost: String,
    val issuer: String,
    val audience: String,
    val allowedEmails: Set<String>,
    val botToken: String,
    val recipients: Map<String, String>,
    val downloadHosts: Set<String>,
    val maxFileBytes: Int = 20 * 1024 * 1024,
    val sendsEnabled: Boolean = false,
) {
    init {
        require(publicHost.matches(Regex("[a-z0-9.-]+"))) { "Invalid MCP_PUBLIC_HOST" }
        val issuerUrl = Url(issuer)
        require(issuerUrl.protocol == URLProtocol.HTTPS && issuerUrl.host.endsWith(".cloudflareaccess.com") &&
            issuerUrl.encodedPath in listOf("", "/") && issuerUrl.parameters.isEmpty() &&
            issuerUrl.user == null && issuerUrl.password == null && issuerUrl.port == 443) { "Invalid CF_ACCESS_ISSUER" }
        require(audience.isNotBlank() && allowedEmails.isNotEmpty() && allowedEmails.all { it.contains('@') && it.none(Char::isWhitespace) }) { "Access audience and allowed emails are required" }
        require(botToken.matches(Regex("[0-9]+:[A-Za-z0-9_-]+"))) { "Invalid Telegram token" }
        require(recipients.isNotEmpty() && recipients.keys.all {
            it.matches(Regex("[A-Za-z][A-Za-z0-9_-]*")) && !it.equals("me", ignoreCase = true)
        }) { "Recipients must have explicit names; me and numeric aliases are forbidden" }
        require(recipients.values.all { it.matches(Regex("[1-9][0-9]*")) }) { "Recipients must map to private Telegram chat IDs" }
        require(downloadHosts.isNotEmpty() && downloadHosts.all {
            it.removePrefix("*.").matches(Regex("[a-z0-9]+(?:[.-][a-z0-9]+)*")) &&
                (!it.startsWith("*.") || it.removePrefix("*.").contains('.'))
        }) { "Download hosts must be exact hostnames or *.domain patterns" }
        require(maxFileBytes in 1..(50 * 1024 * 1024))
    }

    fun allowsDownloadHost(host: String): Boolean {
        val normalized = host.lowercase()
        return downloadHosts.any { pattern ->
            if (pattern.startsWith("*."))
                normalized.endsWith(pattern.removePrefix("*"))
            else normalized == pattern
        }
    }

    companion object {
        fun load(env: (String) -> String?, readSecret: (String) -> String): Config {
            fun required(key: String) = requireNotNull(env(key)?.takeIf { it.isNotBlank() }) { "Missing $key" }
            return Config(
                publicHost = required("MCP_PUBLIC_HOST"),
                issuer = required("CF_ACCESS_ISSUER").trimEnd('/'),
                audience = required("CF_ACCESS_AUDIENCE"),
                allowedEmails = required("CF_ACCESS_ALLOWED_EMAIL").split(',').map { it.trim().lowercase() }.toSet(),
                botToken = env("TELEGRAM_BOT_TOKEN_FILE")?.let(readSecret)?.trim() ?: required("TELEGRAM_BOT_TOKEN"),
                recipients = Json.decodeFromString<Map<String, String>>(required("TELEGRAM_RECIPIENTS")),
                downloadHosts = (env("FILE_DOWNLOAD_HOSTS") ?: "files.oaiusercontent.com").split(',').map { it.trim().lowercase() }.toSet(),
                maxFileBytes = env("MAX_FILE_BYTES")?.toInt() ?: 20 * 1024 * 1024,
                sendsEnabled = env("TELEGRAM_SEND_ENABLED") == "true",
            )
        }
    }
}
