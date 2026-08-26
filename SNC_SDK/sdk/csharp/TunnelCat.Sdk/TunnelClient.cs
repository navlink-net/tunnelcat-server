// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TunnelCat.Sdk;

/// <summary>Thrown when tunneld returns an {"error": ...} response, or on transport failure.</summary>
public class TunnelException : Exception
{
    public TunnelException(string message) : base(message) { }
}

public record ConnectParams(
    string Server,
    string ApiKey = "",
    string Username = "",
    string Password = "",
    string SocksAddr = "",
    /// <summary>cmd/mockserver (and tunnelcat-server's own test stub) only support polling mode.</summary>
    bool PollingOnly = false
);

/// <summary>
/// Spawns tunneld and drives it over its Unix-socket JSON-RPC protocol
/// (see docs/IPC.md). No tunnel logic lives here — this is purely a
/// process-and-socket wrapper, same shape as the Python and Kotlin adapters.
/// </summary>
public sealed class TunnelClient : IDisposable
{
    private readonly string? _tunneldPath;
    private readonly string _socketPath;
    private readonly Action<JsonObject>? _onEvent;
    private readonly TimeSpan _connectTimeout;

    private Process? _process;
    private Socket? _socket;
    private NetworkStream? _stream;
    private int _nextId = 1;
    private readonly ConcurrentDictionary<int, SemaphoreSlim> _pendingSignals = new();
    private readonly ConcurrentDictionary<int, JsonObject> _pendingResults = new();
    private Thread? _readerThread;
    private volatile bool _closed;

    public TunnelClient(
        string? tunneldPath = null,
        string? socketPath = null,
        Action<JsonObject>? onEvent = null,
        TimeSpan? connectTimeout = null)
    {
        _tunneldPath = tunneldPath;
        _socketPath = socketPath ?? Path.Combine(Path.GetTempPath(), $"tunneld-{Guid.NewGuid():N}.sock");
        _onEvent = onEvent;
        _connectTimeout = connectTimeout ?? TimeSpan.FromSeconds(5);
    }

    public void Start()
    {
        var binary = _tunneldPath ?? FindTunneld()
            ?? throw new TunnelException(
                "tunneld binary not found; pass tunneldPath explicitly or put a built " +
                "tunneld(.exe) on PATH");

        if (File.Exists(_socketPath)) File.Delete(_socketPath);

        _process = Process.Start(new ProcessStartInfo
        {
            FileName = binary,
            ArgumentList = { "-socket", _socketPath },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        }) ?? throw new TunnelException("failed to start tunneld process");

        var deadline = DateTime.UtcNow + _connectTimeout;
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(_socketPath)) break;
            if (_process.HasExited) throw new TunnelException("tunneld exited before creating its socket");
            Thread.Sleep(50);
        }
        if (!File.Exists(_socketPath)) throw new TunnelException("timed out waiting for tunneld socket");

        _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _socket.Connect(new UnixDomainSocketEndPoint(_socketPath));
        _stream = new NetworkStream(_socket, ownsSocket: false);

        _readerThread = new Thread(ReadLoop) { IsBackground = true, Name = "tunnelcat-sdk-reader" };
        _readerThread.Start();
    }

    private void ReadLoop()
    {
        try
        {
            using var reader = new StreamReader(_stream!, Encoding.UTF8);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var msg = JsonNode.Parse(line)?.AsObject();
                if (msg is null) continue;

                if (msg.ContainsKey("event"))
                {
                    _onEvent?.Invoke(msg);
                    continue;
                }
                if (msg.TryGetPropertyValue("id", out var idNode) && idNode is not null)
                {
                    var id = idNode.GetValue<int>();
                    _pendingResults[id] = msg;
                    if (_pendingSignals.TryGetValue(id, out var sem)) sem.Release();
                }
            }
        }
        catch
        {
            // socket closed
        }
    }

    private JsonObject? Call(string method, JsonObject? parameters = null, int timeoutSeconds = 15)
    {
        if (_socket is null) throw new TunnelException("not started; call Start() first");

        var id = Interlocked.Increment(ref _nextId);
        var sem = new SemaphoreSlim(0, 1);
        _pendingSignals[id] = sem;

        var req = new JsonObject { ["id"] = id, ["method"] = method };
        if (parameters is not null) req["params"] = parameters;

        var bytes = Encoding.UTF8.GetBytes(req.ToJsonString() + "\n");
        _stream!.Write(bytes, 0, bytes.Length);
        _stream.Flush();

        if (!sem.Wait(TimeSpan.FromSeconds(timeoutSeconds)))
        {
            _pendingSignals.TryRemove(id, out _);
            throw new TunnelException($"timed out waiting for {method} response");
        }
        _pendingResults.TryRemove(id, out var resp);
        _pendingSignals.TryRemove(id, out _);

        var err = resp?["error"]?.GetValue<string>();
        if (!string.IsNullOrEmpty(err)) throw new TunnelException(err);
        return resp?["result"]?.AsObject();
    }

    public JsonObject? Connect(ConnectParams p) => Call("connect", new JsonObject
    {
        ["server"] = p.Server,
        ["apikey"] = p.ApiKey,
        ["username"] = p.Username,
        ["password"] = p.Password,
        ["socksAddr"] = p.SocksAddr,
        ["pollingOnly"] = p.PollingOnly,
    });

    public JsonObject? Disconnect() => Call("disconnect");
    public JsonObject? Status() => Call("status");
    public JsonObject? Reconnect() => Call("reconnect");

    public void Dispose()
    {
        if (_closed) return;
        _closed = true;
        try { _socket?.Close(); } catch { /* ignore */ }
        if (_process is not null)
        {
            try
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(5000);
            }
            catch { /* ignore */ }
        }
        try { if (File.Exists(_socketPath)) File.Delete(_socketPath); } catch { /* ignore */ }
    }

    private static string? FindTunneld()
    {
        var name = OperatingSystem.IsWindows() ? "tunneld.exe" : "tunneld";
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator))
        {
            var candidate = Path.Combine(dir, name);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}
