package io.heapy.telegrammcp

import io.ktor.client.HttpClient
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.*
import io.modelcontextprotocol.kotlin.sdk.server.*
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.*

fun Application.telegramMcp(config: Config, client: HttpClient) {
    val verifier = AccessVerifier(config, client)
    val sender = TelegramSender(config, client)
    install(createApplicationPlugin("CloudflareAccess") {
        onCall { call ->
            if (call.request.path() != "/health") {
                try {
                    verifier.verify(call.request.headers["Cf-Access-Jwt-Assertion"])
                } catch (e: CancellationException) { throw e
                } catch (_: AccessUnavailable) {
                    call.respondText("Authentication service unavailable", status = HttpStatusCode.ServiceUnavailable)
                } catch (_: Exception) {
                    call.response.headers.append(HttpHeaders.WWWAuthenticate,
                        "Bearer resource_metadata=\"https://${config.publicHost}/.well-known/oauth-protected-resource\"")
                    call.respondText("Unauthorized", status = HttpStatusCode.Unauthorized)
                }
            }
        }
    })
    routing { get("/health") { call.respondText("OK") } }
    mcpStatelessStreamableHttp(
        allowedHosts = listOf(config.publicHost, "localhost", "127.0.0.1"),
        allowedOrigins = listOf("https://${config.publicHost}", "https://chatgpt.com"),
    ) { buildServer(sender) { code -> log.warn("send_to_telegram rejected: $code") } }
}

internal fun buildServer(sender: TelegramSender, reportRejection: (String) -> Unit = {}): Server {
    val server = Server(Implementation("send-to-my-telegram", "0.3.4"),
        ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))))
    server.addTool(
        name = "send_to_telegram",
        title = "Send to my Telegram",
        description = "Send the attached file to one allowed Telegram recipient. Pass the actual ChatGPT attachment in file so ChatGPT supplies its temporary download_url and file_id. Never invent a download URL or put a sandbox path in download_url. Require an explicit recipient name from the listed choices. There is no default; me and numeric IDs are not accepted. Ask the user to choose a name if unclear. Each call sends to exactly one chat. Use only when the user requests sending to Telegram. A successful call returns the Telegram message ID. Do not retry an uncertain delivery without checking the chat.",
        inputSchema = ToolSchema(properties = buildJsonObject {
            put("file", buildJsonObject {
                put("type", "object")
                put("properties", buildJsonObject {
                    for (name in listOf("download_url", "file_id", "mime_type", "file_name"))
                        put(name, buildJsonObject { put("type", "string") })
                })
                put("required", JsonArray(listOf(JsonPrimitive("download_url"), JsonPrimitive("file_id"))))
                put("additionalProperties", false)
            })
            put("recipient", buildJsonObject {
                put("type", "string")
                put("enum", JsonArray(sender.allowedRecipients.map { JsonPrimitive(it) }))
                put("description", "Required exact recipient name. No default. Do not use me or a numeric Telegram ID.")
            })
            put("caption", buildJsonObject { put("type", "string"); put("maxLength", 1024) })
        }, required = listOf("file", "recipient")),
        toolAnnotations = ToolAnnotations(readOnlyHint = false, destructiveHint = false, idempotentHint = false, openWorldHint = true),
        meta = buildJsonObject {
            put("openai/fileParams", JsonArray(listOf(JsonPrimitive("file"))))
            put("securitySchemes", JsonArray(listOf(buildJsonObject { put("type", "oauth2"); put("scopes", JsonArray(emptyList())) })))
        },
    ) { request ->
        try {
            val input = parseSendInput(request.arguments ?: JsonObject(emptyMap()))
            val messageId = sender.send(input)
            CallToolResult(content = listOf(TextContent("Sent to Telegram recipient ${input.recipient}. Message ID: $messageId")),
                structuredContent = buildJsonObject { put("message_id", messageId); put("status", "sent"); put("recipient", input.recipient) })
        } catch (e: CancellationException) { throw e
        } catch (e: InvalidInput) {
            reportRejection(e.code + (e.rejectedHost?.let { " host=$it" } ?: ""))
            CallToolResult(content = listOf(TextContent("${e.code}: ${e.safeMessage}")), isError = true)
        } catch (e: SendFailed) {
            CallToolResult(content = listOf(TextContent(e.safeMessage)), isError = true)
        } catch (_: IllegalArgumentException) {
            reportRejection("FILE_METADATA_INVALID")
            CallToolResult(content = listOf(TextContent("Invalid request. An explicit listed recipient name is required. Use an allowed HTTPS download host and a valid file name; caption limit is 1024 characters.")), isError = true)
        } catch (_: Exception) {
            CallToolResult(content = listOf(TextContent("Request failed. Check your Telegram chat before retrying.")), isError = true)
        }
    }
    return server
}
