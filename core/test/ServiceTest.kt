package io.heapy.telegrammcp

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import kotlin.io.encoding.Base64
import kotlin.test.*
import kotlin.time.Clock

class ServiceTest {
    private val config = Config("tgpt-mcp.example.com", "https://test.cloudflareaccess.com", "test-aud",
        setOf("owner@example.com"), "123:test", mapOf("Alice" to "100001", "Bob" to "100002", "Charlie" to "100003"), setOf("files.oaiusercontent.com"), sendsEnabled = true)
    private val now get() = Clock.System.now().epochSeconds
    private fun claims() = buildJsonObject {
        put("iss", config.issuer); put("aud", JsonArray(listOf(JsonPrimitive(config.audience))))
        put("sub", "owner-subject"); put("email", config.allowedEmails.single()); put("type", "app")
        put("iat", now - 10); put("exp", now + 600)
    }
    private fun file() = SendInput(InputFile("https://files.oaiusercontent.com/file?sig=secret", "file_1", "report.pdf", "application/pdf"), "Report", "Charlie")

    @Test fun rejectsWrongIdentityAndClaims() {
        validateClaims(claims(), config, now)
        for ((name, value) in listOf(
            "iss" to JsonPrimitive("https://attacker.example.com"),
            "aud" to JsonPrimitive("different-app"),
            "email" to JsonPrimitive("other@example.com"),
            "exp" to JsonPrimitive(now), "nbf" to JsonPrimitive(now + 60),
            "iat" to JsonPrimitive(now + 60), "type" to JsonPrimitive("service"), "sub" to JsonPrimitive(""),
        )) assertFailsWith<AccessDenied>(name) { validateClaims(JsonObject(claims() + (name to value)), config, now) }
        for (name in listOf("exp", "iat", "iss", "aud", "email", "sub"))
            assertFailsWith<AccessDenied>(name) { validateClaims(JsonObject(claims() - name), config, now) }
    }

    @Test fun rejectsUnsafeFileUrlsAndMetadata() {
        validateFile(file(), config)
        for (url in listOf("http://files.oaiusercontent.com/file", "https://127.0.0.1/file",
            "https://files.oaiusercontent.com.attacker.com/file", "https://files.oaiusercontent.com@attacker.com/",
            "https://files.oaiusercontent.com:8443/file", "https://files.oaiusercontent.com/file#fragment"))
            assertFailsWith<IllegalArgumentException>(url) { validateFile(file().copy(file = file().file.copy(downloadUrl = url)), config) }
        for (name in listOf("../report.pdf", "bad\r\nHeader: injected", "bad\"name", ""))
            assertFailsWith<IllegalArgumentException> { validateFile(file().copy(file = file().file.copy(fileName = name)), config) }
        assertFailsWith<IllegalArgumentException> { validateFile(file().copy(caption = "x".repeat(1025)), config) }
    }

    @Test fun verifiesRealSignatureAndRejectsTampering(): Unit = runBlocking {
        val pair = CryptographyProvider.Default.get(RSA.PKCS1).keyPairGenerator(2048.bits, SHA256).generateKey()
        val jwk = Json.parseToJsonElement(pair.publicKey.encodeToByteArray(RSA.PublicKey.Format.JWK).decodeToString()).jsonObject
        var fetches = 0
        val http = HttpClient(MockEngine { request ->
            assertEquals("${config.issuer}/cdn-cgi/access/certs", request.url.toString())
            fetches++
            respond(buildJsonObject { put("keys", JsonArray(listOf(JsonObject(jwk + ("kid" to JsonPrimitive("test")))))) }.toString(), headers = headersOf(HttpHeaders.ContentType, "application/json"))
        })
        try {
            fun encode(s: String) = Base64.UrlSafe.encode(s.encodeToByteArray()).trimEnd('=')
            val unsigned = encode("""{"alg":"RS256","kid":"test"}""") + "." + encode(claims().toString())
            val signature = Base64.UrlSafe.encode(pair.privateKey.signatureGenerator().generateSignature(unsigned.encodeToByteArray())).trimEnd('=')
            val verifier = AccessVerifier(config, http)
            assertEquals("owner-subject", verifier.verify("$unsigned.$signature"))
            assertEquals("owner-subject", verifier.verify("$unsigned.$signature"))
            assertEquals(1, fetches)
            val altered = unsigned.substringBefore('.') + "." + encode(JsonObject(claims() + ("sub" to JsonPrimitive("attacker"))).toString())
            assertFailsWith<AccessDenied> { verifier.verify("$altered.$signature") }
            assertFailsWith<AccessDenied> { verifier.verify(encode("""{"alg":"none","kid":"test"}""") + "." + encode(claims().toString()) + ".") }
            assertFailsWith<AccessDenied> { verifier.verify(null) }
            assertFailsWith<AccessDenied> { verifier.verify("malformed") }
        } finally { http.close() }
    }

    @Test fun unauthenticatedMcpCannotListOrCallTools() = testApplication {
        val outbound = HttpClient(MockEngine { error("No external requests are permitted") })
        application { telegramMcp(config, outbound) }
        assertEquals(HttpStatusCode.OK, client.get("/health").status)
        for (body in listOf(
            """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""",
            """{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_to_telegram","arguments":{}}}"""
        )) {
            val response = client.post("/mcp") { contentType(ContentType.Application.Json); setBody(body) }
            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertTrue(response.headers[HttpHeaders.WWWAuthenticate]!!.contains("oauth-protected-resource"))
        }
        assertEquals(HttpStatusCode.Unauthorized, client.post("/mcp") { header("Cf-Access-Jwt-Assertion", "forged") }.status)
        outbound.close()
    }

    @Test fun sendsOnlyToConfiguredChatAndReturnsMessageId(): Unit = runBlocking {
        val urls = mutableListOf<String>()
        val http = HttpClient(MockEngine { request ->
            urls += request.url.host
            if (request.url.host == "files.oaiusercontent.com") respond("PDF content")
            else {
                assertEquals("api.telegram.org", request.url.host)
                assertEquals(HttpMethod.Post, request.method)
                val body = request.body.toByteArray().decodeToString()
                assertTrue(body.contains("name=chat_id") || body.contains("name=\"chat_id\""))
                assertTrue(body.contains(config.recipients.getValue("Charlie")))
                assertTrue(body.contains("report.pdf"))
                assertTrue(body.contains("PDF content"))
                respond("""{"ok":true,"result":{"message_id":42}}""", headers = headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }) { followRedirects = false }
        try {
            assertEquals(42L, TelegramSender(config, http).send(file()))
            assertEquals(listOf("files.oaiusercontent.com", "api.telegram.org"), urls)
        } finally { http.close() }
    }

    @Test fun rejectsRedirectsOversizedAndEmptyDownloadsBeforeUpload(): Unit = runBlocking {
        for (kind in listOf("redirect", "oversized", "empty")) {
            var requests = 0
            val http = HttpClient(MockEngine {
                requests++
                when (kind) {
                    "redirect" -> respond("", HttpStatusCode.Found, headersOf(HttpHeaders.Location, "http://127.0.0.1/secret"))
                    "oversized" -> respond("x".repeat(101))
                    else -> respond("")
                }
            }) { followRedirects = false }
            try {
                assertFailsWith<SendFailed>(kind) { TelegramSender(config.copy(maxFileBytes = 100), http).send(file()) }
                assertEquals(1, requests)
            } finally { http.close() }
        }
    }

    @Test fun disabledSendingNeverDownloadsOrUploads(): Unit = runBlocking {
        val http = HttpClient(MockEngine { error("Must not reach the network") })
        try { assertFailsWith<SendFailed> { TelegramSender(config.copy(sendsEnabled = false), http).send(file()) } }
        finally { http.close() }
    }

    @Test fun telegramFailureIsNotRetriedAndDoesNotExposeToken(): Unit = runBlocking {
        var uploads = 0
        val http = HttpClient(MockEngine {
            if (it.url.host == "files.oaiusercontent.com") respond("document")
            else { uploads++; error("Network error at ${it.url}") }
        })
        try {
            val error = assertFailsWith<SendFailed> { TelegramSender(config, http).send(file()) }
            assertFalse(error.safeMessage.contains(config.botToken))
            assertTrue(error.safeMessage.contains("before retrying"))
            assertEquals(1, uploads)
        } finally { http.close() }
    }
    @Test fun authenticatedMcpExposesFileToolAndHonorsSendingGate(): Unit = runBlocking {
        val pair = CryptographyProvider.Default.get(RSA.PKCS1).keyPairGenerator(2048.bits, SHA256).generateKey()
        val jwk = Json.parseToJsonElement(pair.publicKey.encodeToByteArray(RSA.PublicKey.Format.JWK).decodeToString()).jsonObject
        fun encode(s: String) = Base64.UrlSafe.encode(s.encodeToByteArray()).trimEnd('=')
        val unsigned = encode("""{"alg":"RS256","kid":"test"}""") + "." + encode(claims().toString())
        val token = unsigned + "." + Base64.UrlSafe.encode(pair.privateKey.signatureGenerator().generateSignature(unsigned.encodeToByteArray())).trimEnd('=')
        val outbound = HttpClient(MockEngine {
            assertEquals("test.cloudflareaccess.com", it.url.host)
            respond(buildJsonObject { put("keys", JsonArray(listOf(JsonObject(jwk + ("kid" to JsonPrimitive("test")))))) }.toString(),
                headers = headersOf(HttpHeaders.ContentType, "application/json"))
        })
        try {
            testApplication {
                application { telegramMcp(config.copy(sendsEnabled = false), outbound) }
                suspend fun rpc(body: String, origin: String? = null) = client.post("/mcp") {
                    header(HttpHeaders.Host, config.publicHost)
                    header("Cf-Access-Jwt-Assertion", token)
                    header(HttpHeaders.Accept, "application/json, text/event-stream")
                    header("MCP-Protocol-Version", "2025-11-25")
                    origin?.let { header(HttpHeaders.Origin, it) }
                    contentType(ContentType.Application.Json)
                    setBody(body)
                }
                val init = rpc("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}""")
                assertEquals(HttpStatusCode.OK, init.status, init.bodyAsText())
                val listed = rpc("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""")
                assertEquals(HttpStatusCode.OK, listed.status, listed.bodyAsText())
                val tool = Json.parseToJsonElement(listed.bodyAsText()).jsonObject.getValue("result").jsonObject.getValue("tools").jsonArray.single().jsonObject
                assertEquals("send_to_telegram", tool.getValue("name").jsonPrimitive.content)
                assertEquals("file", tool.getValue("_meta").jsonObject.getValue("openai/fileParams").jsonArray.single().jsonPrimitive.content)
                val choices = tool.getValue("inputSchema").jsonObject.getValue("properties").jsonObject.getValue("recipient").jsonObject
                assertEquals(listOf("Alice", "Bob", "Charlie"), choices.getValue("enum").jsonArray.map { it.jsonPrimitive.content })
                assertFalse("default" in choices)
                assertTrue("recipient" in tool.getValue("inputSchema").jsonObject.getValue("required").jsonArray.map { it.jsonPrimitive.content })
                val schema = tool.getValue("inputSchema").jsonObject.getValue("properties").jsonObject.getValue("file").jsonObject
                assertEquals(setOf("download_url", "file_id"), schema.getValue("required").jsonArray.map { it.jsonPrimitive.content }.toSet())
                assertEquals(setOf("download_url", "file_id", "file_name", "mime_type"), schema.getValue("properties").jsonObject.keys)
                val called = rpc("""{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_to_telegram","arguments":{"recipient":"Charlie","file":{"file_id":"file_1","download_url":"https://files.oaiusercontent.com/test"}}}}""")
                assertEquals(HttpStatusCode.OK, called.status)
                val result = Json.parseToJsonElement(called.bodyAsText()).jsonObject.getValue("result").jsonObject
                assertTrue(result.getValue("isError").jsonPrimitive.boolean)
                assertTrue(result.toString().contains("disabled"))
                assertEquals(HttpStatusCode.Forbidden, rpc("""{"jsonrpc":"2.0","id":4,"method":"tools/list"}""", "https://attacker.example.com").status)
            }
        } finally { outbound.close() }
    }

    @Test fun choosesExactlyOneAllowlistedRecipientPerCall(): Unit = runBlocking {
        val uploaded = mutableListOf<String>()
        val http = HttpClient(MockEngine { request ->
            if (request.url.host == "files.oaiusercontent.com") respond("document")
            else {
                val body = request.body.toByteArray().decodeToString()
                val selected = config.recipients.filterValues { body.contains("\r\n\r\n$it\r\n") }.keys
                assertEquals(1, selected.size, "One request must contain exactly one selected recipient")
                uploaded += selected.single()
                respond("""{"ok":true,"result":{"message_id":42}}""", headers = headersOf(HttpHeaders.ContentType, "application/json"))
            }
        })
        try {
            val sender = TelegramSender(config, http)
            for (name in listOf("Alice", "Bob", "Charlie")) sender.send(file().copy(recipient = name))
            assertEquals(listOf("Alice", "Bob", "Charlie"), uploaded)
        } finally { http.close() }
    }

    @Test fun rejectsUnlistedRecipientBeforeAnyNetworkCall(): Unit = runBlocking {
        val http = HttpClient(MockEngine { error("An unlisted recipient must never reach the network") })
        try {
            for (recipient in listOf("me", "Me", "ME", "100001", "100002", "100003", "alice", "all", "", "me,100002", "-100123456")) {
                val error = assertFailsWith<SendFailed> { TelegramSender(config, http).send(file().copy(recipient = recipient)) }
                assertTrue(error.safeMessage.startsWith("Unknown recipient"))
            }
            assertFailsWith<IllegalArgumentException> { config.copy(recipients = mapOf("Alice" to "-100123456")) }
        } finally { http.close() }
    }

    @Test fun requiresNamedRecipientAndRejectsUnsafeConfiguration() {
        assertFailsWith<IllegalArgumentException> {
            Json.decodeFromString<SendInput>("""{"file":{"file_id":"file_1","download_url":"https://files.oaiusercontent.com/test"}}""")
        }
        for (alias in listOf("me", "Me", "ME", "100002", "")) {
            assertFailsWith<IllegalArgumentException> { config.copy(recipients = mapOf(alias to "100002")) }
        }
        assertFailsWith<IllegalArgumentException> { config.copy(recipients = emptyMap()) }
    }
    @Test fun distinguishesMissingUrlSandboxPathAndDisallowedHost() {
        val missing = assertFailsWith<InvalidInput> {
            parseSendInput(Json.parseToJsonElement("""{"recipient":"Charlie","file":{"file_id":"internal-secret"}}""").jsonObject)
        }
        assertEquals("DOWNLOAD_URL_MISSING", missing.code)
        assertFalse(missing.safeMessage.contains("internal-secret"))
        val bare = assertFailsWith<InvalidInput> {
            parseSendInput(Json.parseToJsonElement("""{"recipient":"Charlie","file":"sandbox:/mnt/data/private.txt"}""").jsonObject)
        }
        assertEquals("FILE_OBJECT_MISSING", bare.code)
        for ((url, code) in listOf(
            "sandbox:/mnt/data/private.txt" to "DOWNLOAD_URL_NOT_HTTPS",
            "https://other.example.com/private?sig=secret" to "DOWNLOAD_HOST_NOT_ALLOWED",
        )) {
            val error = assertFailsWith<InvalidInput> { validateFile(file().copy(file = file().file.copy(downloadUrl = url)), config) }
            assertEquals(code, error.code)
            if (code == "DOWNLOAD_HOST_NOT_ALLOWED") {
                assertEquals("other.example.com", error.rejectedHost)
                assertTrue(error.safeMessage.contains("other.example.com"))
                assertFalse(error.safeMessage.contains("https://"))
            }
            assertFalse(error.safeMessage.contains("private"))
            assertFalse(error.safeMessage.contains("secret"))
        }
        val valid = parseSendInput(Json.parseToJsonElement("""{"recipient":"Charlie","file":{"file_id":"file_1","download_url":"https://files.oaiusercontent.com/test"}}""").jsonObject)
        assertEquals("Charlie", valid.recipient)
    }

    @Test fun wildcardDownloadHostsRespectDomainBoundaries() {
        val wildcard = config.copy(downloadHosts = setOf("files.oaiusercontent.com", "*.blob.core.windows.net"))
        for (host in listOf("oaisdmntprnortheu.blob.core.windows.net", "anotherregion.blob.core.windows.net", "ACCOUNT.BLOB.CORE.WINDOWS.NET", "files.oaiusercontent.com"))
            validateFile(file().copy(file = file().file.copy(downloadUrl = "https://$host/file")), wildcard)
        for (host in listOf("blob.core.windows.net", "evilblob.core.windows.net", "account.blob.core.windows.net.attacker.com", "127.0.0.1", "localhost", "sub.files.oaiusercontent.com")) {
            assertFalse(wildcard.allowsDownloadHost(host), host)
            assertFailsWith<InvalidInput>(host) { validateFile(file().copy(file = file().file.copy(downloadUrl = "https://$host/file")), wildcard) }
        }
        for (url in listOf("http://account.blob.core.windows.net/file", "https://account.blob.core.windows.net:8443/file", "https://user:password@account.blob.core.windows.net/file"))
            assertFailsWith<InvalidInput>(url) { validateFile(file().copy(file = file().file.copy(downloadUrl = url)), wildcard) }
        for (pattern in listOf("*", "*.net", "*blob.core.windows.net", "https://blob.core.windows.net", "*.blob..core.windows.net"))
            assertFailsWith<IllegalArgumentException>(pattern) { config.copy(downloadHosts = setOf(pattern)) }
    }

    @Test fun acceptsBothAllowedEmailsButRejectsOthersAndExpiredTokens() {
        val multi = config.copy(allowedEmails = setOf("owner@example.com", "bob@example.com"))
        for (email in listOf("owner@example.com", "bob@example.com", "BOB@EXAMPLE.COM")) {
            val valid = JsonObject(claims() + ("email" to JsonPrimitive(email)))
            validateClaims(valid, multi, now)
            assertFailsWith<AccessDenied> {
                validateClaims(JsonObject(valid + ("exp" to JsonPrimitive(now))), multi, now)
            }
        }
        for (email in listOf("", "other@example.com", "bob@example.com.evil")) {
            assertFailsWith<AccessDenied> {
                validateClaims(JsonObject(claims() + ("email" to JsonPrimitive(email))), multi, now)
            }
        }
        assertFailsWith<IllegalArgumentException> { config.copy(allowedEmails = emptySet()) }
    }

}
