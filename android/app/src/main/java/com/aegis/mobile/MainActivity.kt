package com.aegis.mobile

import android.os.Bundle
import android.content.Context
import androidx.compose.ui.platform.LocalContext
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import android.util.Base64

private val Night = Color(0xFF070B0A)
private val Panel = Color(0xFF101916)
private val Emerald = Color(0xFF35D6A0)
private val Muted = Color(0xFF9BAFA7)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { AegisApp() }
    }
}

@Composable
private fun AegisApp() {
    var endpoint by remember { mutableStateOf("https://aegis-backend-aume.onrender.com") }
    var status by remember { mutableStateOf("Not connected") }
    var identityCode by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    MaterialTheme(colorScheme = darkColorScheme(primary = Emerald, background = Night, surface = Panel)) {
        Column(Modifier.fillMaxSize().background(Night).verticalScroll(rememberScrollState()).padding(22.dp)) {
            Text("AEGIS", color = Emerald, fontSize = 14.sp, fontWeight = FontWeight.Bold, letterSpacing = 5.sp)
            Spacer(Modifier.height(8.dp))
            Text("PRIVATE. VERIFIED. IN CONTROL.", color = Color.White, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Text("Native Android • secure device foundation", color = Muted, fontSize = 13.sp)
            Spacer(Modifier.height(26.dp))
            Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(18.dp)) {
                Column(Modifier.padding(18.dp)) {
                    Text("DEVICE IDENTITY", color = Emerald, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
                    Spacer(Modifier.height(10.dp))
                    Text(if (identityCode.isBlank()) "No Android device identity enrolled" else identityCode, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(8.dp))
                    Text("A separate P-256 key is generated and kept in Android Keystore. The private key is not uploaded.", color = Muted, fontSize = 13.sp)
                }
            }
            Spacer(Modifier.height(18.dp))
            OutlinedTextField(value = endpoint, onValueChange = { endpoint = it.trim() }, label = { Text("Backend HTTPS URL") }, singleLine = true, modifier = Modifier.fillMaxWidth(), colors = OutlinedTextFieldDefaults.colors(focusedTextColor = Color.White, unfocusedTextColor = Color.White, focusedBorderColor = Emerald, unfocusedBorderColor = Muted, focusedLabelColor = Emerald, unfocusedLabelColor = Muted))
            Spacer(Modifier.height(12.dp))
            Button(onClick = {
                scope.launch {
                    busy = true
                    status = "Connecting securely…"
                    try {
                        val result = withContext(Dispatchers.IO) { AndroidEnrollment.enroll(context, endpoint.trimEnd('/'), "AEGIS Android") }
                        identityCode = result.first
                        status = "Device enrolled • session stored securely"
                    } catch (e: Exception) { status = e.message ?: "Connection failed" }
                    busy = false
                }
            }, enabled = !busy && endpoint.startsWith("https://"), modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Emerald, contentColor = Night)) {
                if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp), color = Night, strokeWidth = 2.dp) else Text("ENROL THIS ANDROID DEVICE", fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(14.dp))
            Text(status, color = if (status.startsWith("Device enrolled")) Emerald else Muted, fontSize = 13.sp)
            Spacer(Modifier.height(26.dp))
            Text("PLATFORM MODULES", color = Emerald, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
            Spacer(Modifier.height(10.dp))
            listOf("Ghost identity & device trust" to "Android Keystore-backed signing key and existing AEGIS challenge-response API.", "Sentinel & device controls" to "Available through the existing authenticated backend and web dashboard.", "Messenger, Rooms & Vault" to "Not enabled in this alpha; encrypted protocols and storage must be implemented and tested before use.", "Calls & media masking" to "Not enabled in this alpha; no microphone or camera is accessed by this screen.", "VPN & DNS protection" to "Not enabled in this alpha; no network traffic is routed or hidden.", "Workhub" to "Not enabled in this alpha; no data is synced by this screen.").forEach { (title, detail) ->
                Card(Modifier.fillMaxWidth().padding(bottom = 9.dp), colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(14.dp)) {
                    Column(Modifier.padding(14.dp)) { Text(title, color = Color.White, fontWeight = FontWeight.SemiBold); Spacer(Modifier.height(4.dp)); Text(detail, color = Muted, fontSize = 12.sp) }
                }
            }
            Spacer(Modifier.height(16.dp))
            Text("AEGIS alpha • Security features are not independently audited. Do not use this build for high-risk communications.", color = Muted, fontSize = 11.sp)
        }
    }
}

private object AndroidEnrollment {
    private const val KEY_ALIAS = "aegis_android_identity_v1"
    private const val PREFS = "aegis_secure_session"

    fun enroll(context: Context, base: String, label: String): Pair<String, String> {
        require(base.startsWith("https://")) { "HTTPS is required." }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
            generator.initialize(ECGenParameterSpec("secp256r1"))
            generator.generateKeyPair()
        }
        val publicEncoded = keyStore.getCertificate(KEY_ALIAS).publicKey.encoded
        val rawPublic = publicEncoded.takeLast(65).toByteArray()
        require(rawPublic.size == 65 && rawPublic[0].toInt() == 4) { "Could not read the P-256 public key." }
        val publicKey = Base64.encodeToString(rawPublic, Base64.NO_WRAP)
        val challenge = post("$base/v1/challenges", JSONObject().put("publicKey", publicKey))
        val challengeId = challenge.getString("challengeId")
        val message = challenge.getString("message")
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as java.security.PrivateKey
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(message.toByteArray(StandardCharsets.UTF_8))
        val signature = derToP1363(signer.sign())
        val response = post("$base/v1/devices/register", JSONObject()
            .put("publicKey", publicKey)
            .put("challengeId", challengeId)
            .put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
            .put("label", label))
        val token = response.getString("token")
        SecureSessionStore.save(context, token)
        return Pair(response.getJSONObject("device").getString("identity_code"), token)
    }

    private fun post(url: String, body: JSONObject): JSONObject {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"; connectTimeout = 15000; readTimeout = 20000
            doOutput = true; setRequestProperty("Content-Type", "application/json")
        }
        try {
            connection.outputStream.use { it.write(body.toString().toByteArray(StandardCharsets.UTF_8)) }
            val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
            val text = stream.bufferedReader().use { it.readText() }
            val json = JSONObject(text.ifBlank { "{}" })
            if (connection.responseCode !in 200..299) throw IllegalStateException(json.optString("error", "Backend request failed (${connection.responseCode})"))
            return json
        } finally { connection.disconnect() }
    }

    private fun derToP1363(der: ByteArray): ByteArray {
        var i = 0
        require(der[i++].toInt() == 0x30) { "Invalid signature encoding." }
        val seqLength = der[i++].toInt() and 0xff
        require(seqLength <= der.size - i) { "Invalid signature length." }
        fun integer(): ByteArray {
            require(der[i++].toInt() == 0x02) { "Invalid signature integer." }
            val length = der[i++].toInt() and 0xff
            val value = der.copyOfRange(i, i + length); i += length
            val stripped = value.dropWhile { it == 0.toByte() }.toByteArray()
            require(stripped.size <= 32) { "Invalid P-256 signature." }
            return ByteArray(32 - stripped.size) + stripped
        }
        return integer() + integer()
    }
}

private object SecureSessionStore {
    private const val AES_ALIAS = "aegis_session_aes_v1"
    fun save(context: Context, token: String) {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(AES_ALIAS)) {
            val gen = javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore")
            gen.init(android.security.keystore.KeyGenParameterSpec.Builder(AES_ALIAS, android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build())
            gen.generateKey()
        }
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, ks.getKey(AES_ALIAS, null) as javax.crypto.SecretKey)
        val encrypted = cipher.doFinal(token.toByteArray(StandardCharsets.UTF_8))
        val prefs = context.getSharedPreferences("aegis_session", Context.MODE_PRIVATE)
        val packed = cipher.iv + encrypted
        check(prefs.edit().putString("session_blob", Base64.encodeToString(packed, Base64.NO_WRAP)).commit()) { "Could not store the secure session." }
    }
}
