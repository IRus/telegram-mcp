package io.heapy.telegrammcp

import io.ktor.client.HttpClient
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.utils.io.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.io.readByteArray
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.*

@Serializable
data class InputFile(
    @SerialName("download_url") val downloadUrl: String,
    @SerialName("file_id") val fileId: String,
    @SerialName("file_name") val fileName: String? = null,
    @SerialName("mime_type") val mimeType: String? = null,
)
@Serializable
data class SendInput(val file: InputFile, val caption: String? = null, val recipient: String)
class SendFailed(val safeMessage: String) : Exception(safeMessage)
class InvalidInput(val code: String, val safeMessage: String, val rejectedHost: String? = null) : IllegalArgumentException(safeMessage)

internal fun parseSendInput(arguments: JsonObject): SendInput {
    val file = arguments["file"] as? JsonObject
        ?: throw InvalidInput("FILE_OBJECT_MISSING", "ChatGPT did not supply a file object. Pass the attachment through the file parameter, not a bare file_id or sandbox path.")
    val downloadUrl = file["download_url"] as? JsonPrimitive
    if (downloadUrl == null || !downloadUrl.isString || downloadUrl.content.isBlank())
        throw InvalidInput("DOWNLOAD_URL_MISSING", "ChatGPT did not supply download_url for this attachment. A file_id alone cannot be downloaded by this server. Refresh the connection's tools and pass the attachment through the file parameter; do not invent a URL.")
    return try { Json.decodeFromJsonElement<SendInput>(arguments) }
    catch (_: IllegalArgumentException) {
        throw InvalidInput("INPUT_SCHEMA_INVALID", "Invalid input: file must contain download_url and file_id strings, recipient must be an explicit listed name, and caption is optional.")
    }
}


internal fun validateFile(input: SendInput, config: Config): Url {
    require(input.file.fileId.isNotBlank() && input.file.fileId.length <= 512) { "Invalid file_id" }
    require((input.caption?.length ?: 0) <= 1024) { "Caption must be at most 1024 characters" }
    require(input.file.downloadUrl.length <= 16384) { "Download URL is too long" }
    if (!input.file.downloadUrl.startsWith("https://", ignoreCase = true))
        throw InvalidInput("DOWNLOAD_URL_NOT_HTTPS", "The attachment has no HTTPS download URL. Internal file_id values and sandbox:/mnt/data paths are not downloadable by this server. Pass the actual attachment through the file parameter.")
    val url = try { Url(input.file.downloadUrl) } catch (_: IllegalArgumentException) {
        throw InvalidInput("DOWNLOAD_URL_INVALID", "The attachment download URL is malformed.")
    }
    if (url.protocol != URLProtocol.HTTPS || url.port != 443 || url.user != null || url.password != null || url.fragment.isNotEmpty())
        throw InvalidInput("DOWNLOAD_URL_UNSAFE", "The attachment URL must use HTTPS on port 443 without credentials or a fragment.")
    if (!config.allowsDownloadHost(url.host)) {
        val host = url.host.lowercase().takeIf { it.length in 1..253 && it.matches(Regex("[a-z0-9.-]+")) }
        throw InvalidInput("DOWNLOAD_HOST_NOT_ALLOWED",
            "The attachment storage host ${host ?: "(invalid hostname)"} is not allowed. Ask the server administrator to verify this exact host; do not replace the URL.",
            rejectedHost = host)
    }

    val name = input.file.fileName ?: "document"
    require(name.length in 1..240 && name.none { it < ' ' || it == '\u007f' || it in "\"\\/" }) { "Invalid file name" }
    val mime = input.file.mimeType ?: "application/octet-stream"
    require(mime.matches(Regex("[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+"))) { "Invalid MIME type" }
    return url
}

/** Bounded streaming reads, including responses without Content-Length. */
internal suspend fun HttpResponse.readBounded(limit: Int): ByteArray {
    if ((contentLength() ?: 0) > limit) throw SendFailed("Response exceeds the configured size limit")
    val channel = bodyAsChannel()
    val bytes = channel.readRemaining(limit.toLong() + 1).readByteArray()
    if (bytes.size > limit) {
        channel.cancel()
        throw SendFailed("Response exceeds the configured size limit")
    }
    return bytes
}

class TelegramSender(private val config: Config, private val client: HttpClient) {
    val allowedRecipients: List<String> = config.recipients.keys.sorted()

    private fun recipientChatId(recipient: String): String =
        config.recipients[recipient]
            ?: throw SendFailed("Unknown recipient. Choose one of: ${allowedRecipients.joinToString()}")

    // Bound simultaneous file buffers and avoid concurrent sends from repeated clicks.
    private val permits = Semaphore(1)

    suspend fun send(input: SendInput): Long = permits.withPermit {
        val chatId = recipientChatId(input.recipient)
        val url = validateFile(input, config)
        if (!config.sendsEnabled) throw SendFailed("Telegram sending is disabled until authentication setup is verified")
        val bytes = try {
            client.prepareGet(url).execute { response ->
                if (!response.status.isSuccess()) throw SendFailed("File download failed; provide a fresh file attachment")
                response.readBounded(config.maxFileBytes)
            }
        } catch (e: kotlinx.coroutines.CancellationException) { throw e
        } catch (e: SendFailed) { throw e
        } catch (_: Exception) { throw SendFailed("File download failed; provide a fresh file attachment") }
        if (bytes.isEmpty()) throw SendFailed("The file is empty")
        try {
            val response = client.post("https://api.telegram.org/bot${config.botToken}/sendDocument") {
                setBody(MultiPartFormDataContent(formData {
                    append("chat_id", chatId)
                    input.caption?.let { append("caption", it) }
                    append("document", bytes, Headers.build {
                        append(HttpHeaders.ContentType, input.file.mimeType ?: "application/octet-stream")
                        append(HttpHeaders.ContentDisposition, "filename=\"${input.file.fileName ?: "document"}\"")
                    })
                }))
            }
            val result = Json.parseToJsonElement(response.readBounded(64 * 1024).decodeToString()).jsonObject
            if (!response.status.isSuccess() || result["ok"]?.jsonPrimitive?.booleanOrNull != true)
                throw SendFailed("Telegram rejected the document; check bot access and file limits")
            result.getValue("result").jsonObject.getValue("message_id").jsonPrimitive.long
        } catch (e: kotlinx.coroutines.CancellationException) { throw e
        } catch (e: SendFailed) { throw e
        } catch (_: Exception) {
            // Telegram has no idempotency key: a transport failure can happen after acceptance.
            throw SendFailed("Telegram delivery could not be confirmed. Check your chat before retrying to avoid duplicates")
        }
    }
}
