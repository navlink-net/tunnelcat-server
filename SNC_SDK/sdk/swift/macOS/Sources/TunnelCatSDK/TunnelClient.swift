// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Thrown when tunneld returns an {"error": ...} response, or on transport failure.
public struct TunnelError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

public struct ConnectParams {
    public var server: String
    public var apiKey: String = ""
    public var username: String = ""
    public var password: String = ""
    public var socksAddr: String = ""
    /// cmd/mockserver (and tunnelcat-server's own test stub) only support polling mode.
    public var pollingOnly: Bool = false

    public init(server: String, apiKey: String = "", username: String = "", password: String = "",
                socksAddr: String = "", pollingOnly: Bool = false) {
        self.server = server
        self.apiKey = apiKey
        self.username = username
        self.password = password
        self.socksAddr = socksAddr
        self.pollingOnly = pollingOnly
    }
}

/// Spawns tunneld and drives it over its Unix-socket JSON-RPC protocol
/// (see docs/IPC.md). No tunnel logic lives here — this is purely a
/// process-and-socket wrapper, same shape as the Python/Kotlin/C# adapters.
///
/// macOS only: iOS forbids spawning subprocesses, so the iOS target uses
/// sdk/swift/ios's cgo-c-archive adapter instead (see that directory).
public final class TunnelClient {
    private let tunneldPath: String?
    private let socketPath: String
    private let onEvent: (([String: Any]) -> Void)?
    private let connectTimeout: TimeInterval

    private var process: Process?
    private var fd: Int32 = -1
    private var fileHandle: FileHandle?
    private var nextId = 1
    private let lock = NSLock()
    private var pending: [Int: (Result<[String: Any]?, Error>) -> Void] = [:]
    private var readThread: Thread?
    private var closed = false

    public init(tunneldPath: String? = nil, socketPath: String? = nil,
                onEvent: (([String: Any]) -> Void)? = nil, connectTimeout: TimeInterval = 5) {
        self.tunneldPath = tunneldPath
        self.socketPath = socketPath ?? (NSTemporaryDirectory() + "tunneld-\(UUID().uuidString).sock")
        self.onEvent = onEvent
        self.connectTimeout = connectTimeout
    }

    public func start() throws {
        guard let binary = tunneldPath ?? Self.findTunneld() else {
            throw TunnelError("tunneld binary not found; pass tunneldPath explicitly or put a built tunneld on PATH")
        }
        try? FileManager.default.removeItem(atPath: socketPath)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: binary)
        proc.arguments = ["-socket", socketPath]
        try proc.run()
        process = proc

        let deadline = Date().addingTimeInterval(connectTimeout)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: socketPath) { break }
            if !proc.isRunning { throw TunnelError("tunneld exited before creating its socket") }
            Thread.sleep(forTimeInterval: 0.05)
        }
        guard FileManager.default.fileExists(atPath: socketPath) else {
            throw TunnelError("timed out waiting for tunneld socket")
        }

        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw TunnelError("socket() failed") }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes.prefix(raw.count - 1))
        }
        let size = MemoryLayout<sockaddr_un>.size
        let result = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(fd, sa, socklen_t(size))
            }
        }
        guard result == 0 else { throw TunnelError("connect() failed: errno=\(errno)") }

        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        fileHandle = handle

        let thread = Thread { [weak self] in self?.readLoop() }
        thread.name = "tunnelcat-sdk-reader"
        thread.start()
        readThread = thread
    }

    private func readLoop() {
        guard let handle = fileHandle else { return }
        var buffer = Data()
        while true {
            let chunk = handle.availableData
            if chunk.isEmpty { break } // EOF
            buffer.append(chunk)
            while let nl = buffer.firstIndex(of: 0x0A) {
                let lineData = buffer.subdata(in: buffer.startIndex..<nl)
                buffer.removeSubrange(buffer.startIndex...nl)
                guard !lineData.isEmpty,
                      let obj = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any] else { continue }
                if obj["event"] != nil {
                    onEvent?(obj)
                    continue
                }
                if let id = obj["id"] as? Int {
                    lock.lock()
                    let cb = pending.removeValue(forKey: id)
                    lock.unlock()
                    guard let cb = cb else { continue }
                    if let err = obj["error"] as? String, !err.isEmpty {
                        cb(.failure(TunnelError(err)))
                    } else {
                        cb(.success(obj["result"] as? [String: Any]))
                    }
                }
            }
        }
    }

    private func call(_ method: String, params: [String: Any]? = nil, timeout: TimeInterval = 15) throws -> [String: Any]? {
        guard let handle = fileHandle else { throw TunnelError("not started; call start() first") }

        lock.lock()
        let id = nextId
        nextId += 1
        let sem = DispatchSemaphore(value: 0)
        var outcome: Result<[String: Any]?, Error> = .failure(TunnelError("timed out waiting for \(method) response"))
        pending[id] = { result in
            outcome = result
            sem.signal()
        }
        lock.unlock()

        var req: [String: Any] = ["id": id, "method": method]
        if let params = params { req["params"] = params }
        let data = try JSONSerialization.data(withJSONObject: req)
        handle.write(data)
        handle.write("\n".data(using: .utf8)!)

        if sem.wait(timeout: .now() + timeout) == .timedOut {
            lock.lock(); pending.removeValue(forKey: id); lock.unlock()
            throw TunnelError("timed out waiting for \(method) response")
        }
        return try outcome.get()
    }

    @discardableResult
    public func connect(_ p: ConnectParams) throws -> [String: Any]? {
        try call("connect", params: [
            "server": p.server, "apikey": p.apiKey, "username": p.username,
            "password": p.password, "socksAddr": p.socksAddr, "pollingOnly": p.pollingOnly,
        ])
    }

    @discardableResult
    public func disconnect() throws -> [String: Any]? { try call("disconnect") }
    @discardableResult
    public func status() throws -> [String: Any]? { try call("status") }
    @discardableResult
    public func reconnect() throws -> [String: Any]? { try call("reconnect") }

    public func close() {
        guard !closed else { return }
        closed = true
        fileHandle?.closeFile()
        if let p = process, p.isRunning {
            p.terminate()
            p.waitUntilExit()
        }
        try? FileManager.default.removeItem(atPath: socketPath)
    }

    deinit { close() }

    private static func findTunneld() -> String? {
        let path = ProcessInfo.processInfo.environment["PATH"] ?? ""
        for dir in path.split(separator: ":") {
            let candidate = "\(dir)/tunneld"
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }
}
