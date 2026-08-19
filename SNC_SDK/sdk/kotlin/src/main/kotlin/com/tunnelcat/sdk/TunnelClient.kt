// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package com.tunnelcat.sdk

import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.channels.Channels
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject

/** Thrown when tunneld returns an {"error": ...} response, or on transport failure. */
class TunnelError(message: String) : Exception(message)

data class ConnectParams(
    val server: String,
    val apiKey: String = "",
    val username: String = "",
    val password: String = "",
    val socksAddr: String = "",
    /** cmd/mockserver (and tunnelcat-core's own test stub) only support polling mode. */
    val pollingOnly: Boolean = false,
)

/**
 * Spawns tunneld and drives it over its Unix-socket JSON-RPC protocol
 * (see docs/IPC.md). No tunnel logic lives here — this is purely a
 * process-and-socket wrapper, same shape as the Python and C# adapters.
 */
class TunnelClient(
    private val tunneldPath: String? = null,
    private val socketPath: Path = Path.of(
        System.getProperty("java.io.tmpdir"),
        "tunneld-${UUID.randomUUID()}.sock",
    ),
    private val onEvent: ((JSONObject) -> Unit)? = null,
    private val connectTimeoutSeconds: Long = 5,
) : AutoCloseable {

    private var process: Process? = null
    private var channel: SocketChannel? = null
    private var writer: OutputStream? = null
    private val nextId = AtomicInteger(1)
    private val pending = ConcurrentHashMap<Int, SynchronousQueue<JSONObject>>()
    private var readerThread: Thread? = null
    @Volatile private var closed = false

    fun start() {
        val binary = tunneldPath ?: findTunneld()
            ?: throw TunnelError(
                "tunneld binary not found; pass tunneldPath explicitly or put a " +
                    "built tunneld(.exe) on PATH",
            )
        Files.deleteIfExists(socketPath)

        val pb = ProcessBuilder(binary, "-socket", socketPath.toString())
        pb.redirectErrorStream(true)
        process = pb.start()

        val deadline = System.currentTimeMillis() + connectTimeoutSeconds * 1000
        while (System.currentTimeMillis() < deadline) {
            if (Files.exists(socketPath)) break
            if (process?.isAlive == false) {
                throw TunnelError("tunneld exited before creating its socket")
            }
            Thread.sleep(50)
        }
        if (!Files.exists(socketPath)) {
            throw TunnelError("timed out waiting for tunneld socket")
        }

        val addr = UnixDomainSocketAddress.of(socketPath)
        val ch = SocketChannel.open(StandardProtocolFamily.UNIX)
        ch.connect(addr)
        channel = ch
        writer = Channels.newOutputStream(ch)

        readerThread = Thread(this::readLoop, "tunnelcat-sdk-reader").apply {
            isDaemon = true
            start()
        }
    }

    private fun readLoop() {
        try {
            val reader = BufferedReader(InputStreamReader(Channels.newInputStream(channel)))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                val text = line ?: continue
                if (text.isBlank()) continue
                val msg = JSONObject(text)
                if (msg.has("event")) {
                    onEvent?.invoke(msg)
                    continue
                }
                val id = msg.optInt("id", -1)
                pending.remove(id)?.put(msg)
            }
        } catch (_: Exception) {
            // channel closed
        }
    }

    @Synchronized
    private fun call(method: String, params: JSONObject? = null, timeoutSeconds: Long = 15): JSONObject? {
        val ch = channel ?: throw TunnelError("not started; call start() first")
        val id = nextId.getAndIncrement()
        val q = SynchronousQueue<JSONObject>()
        pending[id] = q

        val req = JSONObject().put("id", id).put("method", method)
        if (params != null) req.put("params", params)
        writer!!.write((req.toString() + "\n").toByteArray())
        writer!!.flush()

        val resp = q.poll(timeoutSeconds, TimeUnit.SECONDS)
            ?: run {
                pending.remove(id)
                throw TunnelError("timed out waiting for $method response")
            }

        val err = resp.optString("error", "")
        if (err.isNotEmpty()) throw TunnelError(err)
        return resp.optJSONObject("result")
    }

    fun connect(p: ConnectParams): JSONObject? = call(
        "connect",
        JSONObject()
            .put("server", p.server)
            .put("apikey", p.apiKey)
            .put("username", p.username)
            .put("password", p.password)
            .put("socksAddr", p.socksAddr)
            .put("pollingOnly", p.pollingOnly),
    )

    fun disconnect(): JSONObject? = call("disconnect")
    fun status(): JSONObject? = call("status")
    fun reconnect(): JSONObject? = call("reconnect")

    override fun close() {
        if (closed) return
        closed = true
        runCatching { channel?.close() }
        process?.let {
            it.destroy()
            if (!it.waitFor(5, TimeUnit.SECONDS)) it.destroyForcibly()
        }
        runCatching { Files.deleteIfExists(socketPath) }
    }

    private fun findTunneld(): String? {
        val name = if (System.getProperty("os.name").lowercase().contains("win")) "tunneld.exe" else "tunneld"
        val path = System.getenv("PATH") ?: return null
        for (dir in path.split(File.pathSeparator)) {
            val f = File(dir, name)
            if (f.canExecute()) return f.absolutePath
        }
        return null
    }
}
