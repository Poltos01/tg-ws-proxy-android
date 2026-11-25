package dev.minios.tgwsproxy.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

/**
 * Live end-to-end check of the production data path: a simulated Telegram client talks
 * obfuscated MTProto to the local proxy, the proxy relays over the Cloudflare route to a
 * real data centre and the DC answers resPQ.
 *
 * Skipped unless TGWS_LIVE=1, because it needs real network access.
 */
class LiveCfTransportTest {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var server: TgWsProxyServer? = null
    private var secret: ByteArray = ByteArray(0)
    private val port = 15443

    @Before
    fun setUp() {
        assumeTrue("live network test (set TGWS_LIVE=1)", System.getenv("TGWS_LIVE") == "1")
        secret = ByteArray(16).also { SecureRandom().nextBytes(it) }
    }

    @After
    fun tearDown() {
        server?.stop()
        server = null
        scope.cancel()
    }

    @Test
    fun reqPqThroughCloudflareRoute() = runBlocking {
        val config = ProxyConfig(
            port = port,
            secret = secret.joinToString("") { "%02x".format(it) },
            // No direct DC redirect: every connection must take the Cloudflare route,
            // which is what Android clients rely on for DC1/3/5/203.
            dcRedirects = emptyMap(),
            cfProxyEnabled = true,
            cfProxyFirst = false,
            cfSecure = true,
            cfH2Media = true,
            poolSize = 0,
            preconnectWebSockets = false,
        )
        val srv = TgWsProxyServer(config, ConnectivityTracker())
        server = srv
        scope.launch { srv.start() }
        withTimeout(20_000) { while (!srv.isRunning) delay(50) }

        val nonce = requestResPq(port, secret, dc = 2, timeoutMs = 25_000)
        assertNotNull("no resPQ came back through the Cloudflare route", nonce)
        assertTrue("Cloudflare route must be used", ProxyStats.connectionsCfProxy.get() > 0)
    }

    /** Sends req_pq_multi and returns the echoed nonce when the DC answers with resPQ. */
    private fun requestResPq(port: Int, secret: ByteArray, dc: Int, timeoutMs: Int): ByteArray? {
        val random = SecureRandom()
        var init: ByteArray
        val prekey: ByteArray
        val iv: ByteArray
        while (true) {
            val candidate = ByteArray(64).also { random.nextBytes(it) }
            if (candidate[0].toInt() and 0xFF == 0xEF) continue
            val head = candidate.copyOfRange(0, 4)
            if (head.contentEquals("HEAD".toByteArray()) || head.contentEquals("POST".toByteArray()) ||
                head.contentEquals("GET ".toByteArray()) || head.contentEquals("OPTI".toByteArray())
            ) continue
            if (candidate[4].toInt() == 0 && candidate[5].toInt() == 0 &&
                candidate[6].toInt() == 0 && candidate[7].toInt() == 0
            ) continue
            init = candidate
            prekey = candidate.copyOfRange(8, 40)
            iv = candidate.copyOfRange(40, 56)
            break
        }

        val clientEncryptor = AesCtr(MtProtoCrypto.deriveKey(prekey, secret), iv)
        val keystream = clientEncryptor.update(ByteArray(64))
        val tail = byteArrayOf(
            0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(),
            (dc and 0xFF).toByte(), ((dc shr 8) and 0xFF).toByte(), 0x00, 0x00,
        )
        for (i in 0 until 8) tail[i] = (tail[i].toInt() xor keystream[56 + i].toInt()).toByte()
        System.arraycopy(tail, 0, init, 56, 8)

        val reversed = init.copyOfRange(8, 56).reversedArray()
        val decryptor = AesCtr(
            MtProtoCrypto.deriveKey(reversed.copyOfRange(0, 32), secret),
            reversed.copyOfRange(32, 48),
        )

        val nonce = ByteArray(16).also { random.nextBytes(it) }
        val body = byteArrayOf(0xF1.toByte(), 0x8E.toByte(), 0x7E.toByte(), 0xBE.toByte()) + nonce
        val msgId = ((System.currentTimeMillis() / 1000) shl 32) or
            ((random.nextInt().toLong() and 0x3FFFFFFFL) shl 2)
        val message = ByteArray(8) + leLong(msgId) + leInt(body.size) + body
        val frame = leInt(message.size) + message

        Socket().use { socket ->
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress("127.0.0.1", port), 10_000)
            socket.soTimeout = timeoutMs
            socket.getOutputStream().apply {
                write(init)
                write(clientEncryptor.update(frame))
                flush()
            }
            val input = socket.getInputStream()
            val buffer = ByteArray(8192)
            var pending = ByteArray(0)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val read = try {
                    input.read(buffer)
                } catch (_: java.net.SocketTimeoutException) {
                    break
                }
                if (read <= 0) break
                pending += decryptor.update(buffer.copyOfRange(0, read))
                while (pending.size >= 4) {
                    val length = readIntLE(pending, 0)
                    if (length <= 0 || length > 1 shl 20) return null
                    if (pending.size < 4 + length) break
                    val payload = pending.copyOfRange(4, 4 + length)
                    pending = pending.copyOfRange(4 + length, pending.size)
                    if (payload.size < 28) continue
                    val code = readIntLE(payload, 24)
                    if (code == 0x05162463) {  // resPQ
                        val echoed = payload.copyOfRange(28, 44)
                        assertArrayEquals("resPQ nonce must match", nonce, echoed)
                        return echoed
                    }
                }
            }
        }
        return null
    }

    private fun leInt(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value shr 8) and 0xFF).toByte(),
        ((value shr 16) and 0xFF).toByte(),
        ((value shr 24) and 0xFF).toByte(),
    )

    private fun leLong(value: Long): ByteArray = ByteArray(8) { i ->
        ((value shr (8 * i)) and 0xFF).toByte()
    }

    private fun readIntLE(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8) or
            ((data[offset + 2].toInt() and 0xFF) shl 16) or
            ((data[offset + 3].toInt() and 0xFF) shl 24)
}
