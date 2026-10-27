package io.heapy.telegrammcp

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.http.isSuccess
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.*
import kotlin.io.encoding.Base64
import kotlin.time.Clock

class AccessDenied : Exception("Access denied")
class AccessUnavailable : Exception("Access verification unavailable")

/** Only the configured Cloudflare issuer supplies keys; token jku/x5u URLs are never followed. */
class AccessVerifier(private val config: Config, private val client: HttpClient) {
    private val lock = Mutex()
    private var keys: List<JsonObject> = emptyList()
    private var fetchedAt = 0L

    suspend fun verify(token: String?): String {
        if (token == null || token.length !in 1..16384) throw AccessDenied()
        val parts = token.split('.')
        if (parts.size != 3) throw AccessDenied()
        val header = decodeObject(parts[0])
        if (header["alg"]?.jsonPrimitive?.content != "RS256" || header.containsKey("crit")) throw AccessDenied()
        val kid = header["kid"]?.jsonPrimitive?.content ?: throw AccessDenied()
        val jwk = key(kid)
        val claims = decodeObject(parts[1])
        try {
            val publicKey = CryptographyProvider.Default.get(RSA.PKCS1).publicKeyDecoder(SHA256)
                .decodeFromByteArray(RSA.PublicKey.Format.JWK, jwk.toString().encodeToByteArray())
            publicKey.signatureVerifier().verifySignature(
                "${parts[0]}.${parts[1]}".encodeToByteArray(), Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(parts[2]),
            )
        } catch (e: kotlinx.coroutines.CancellationException) { throw e
        } catch (_: Exception) { throw AccessDenied() }
        validateClaims(claims, config, Clock.System.now().epochSeconds)
        return claims.getValue("sub").jsonPrimitive.content
    }

    private suspend fun key(kid: String): JsonObject = lock.withLock {
        val now = Clock.System.now().epochSeconds
        if (now - fetchedAt >= 3600 || (keys.none { it["kid"]?.jsonPrimitive?.content == kid } && now - fetchedAt >= 60)) {
            try {
                val response = client.get("${config.issuer}/cdn-cgi/access/certs")
                if (!response.status.isSuccess()) throw AccessUnavailable()
                val body = response.readBounded(256 * 1024).decodeToString()
                keys = Json.parseToJsonElement(body).jsonObject.getValue("keys").jsonArray.map { it.jsonObject }
                fetchedAt = now
            } catch (e: kotlinx.coroutines.CancellationException) { throw e
            } catch (_: Exception) { throw AccessUnavailable() }
        }
        keys.singleOrNull { it["kid"]?.jsonPrimitive?.content == kid &&
            it["kty"]?.jsonPrimitive?.content == "RSA" &&
            (it["alg"] == null || it["alg"]?.jsonPrimitive?.content == "RS256") &&
            (it["use"] == null || it["use"]?.jsonPrimitive?.content == "sig")
        } ?: throw AccessDenied()
    }
}

private fun decodeObject(value: String): JsonObject = try {
    Json.parseToJsonElement(Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(value).decodeToString()).jsonObject
} catch (_: Exception) { throw AccessDenied() }

internal fun validateClaims(claims: JsonObject, config: Config, now: Long) {
    fun text(key: String) = (claims[key] as? JsonPrimitive)?.contentOrNull
    fun number(key: String) = (claims[key] as? JsonPrimitive)?.longOrNull
    val audiences = when (val aud = claims["aud"]) {
        is JsonArray -> aud.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        is JsonPrimitive -> listOfNotNull(aud.contentOrNull)
        else -> emptyList()
    }
    if (text("iss") != config.issuer || config.audience !in audiences ||
        (number("exp") ?: 0) <= now || (claims.containsKey("nbf") && (number("nbf") ?: Long.MAX_VALUE) > now) ||
        (number("iat") ?: Long.MAX_VALUE) > now + 30 || text("type") != "app" ||
        text("sub").isNullOrBlank() || config.allowedEmails.none { it.equals(text("email"), ignoreCase = true) }
    ) throw AccessDenied()
}
