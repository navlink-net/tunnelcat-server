// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

import Foundation

/// Thin 1:1 Swift wrapper over cmd/lib-ios's C exports (see Bridging-Header.h).
/// No callback/delegate mechanism exists — status is synchronous call-and-poll
/// (there is no separate process boundary once linked into the app/extension,
/// so there's nothing to push events across).
public enum TunnelState: String, Decodable {
    case idle, connecting, connected, error
}

public struct TunnelStatus: Decodable {
    public let state: TunnelState
    public let error: String?
}

public enum GoCore {
    public static func start(server: String, apiKey: String, username: String,
                              password: String, logDir: String, dataDir: String) -> Bool {
        // TCStart is synchronous — Go copies each C string's contents before
        // returning, so the withCString pointers only need to stay valid for
        // the duration of this call. No strdup/manual free needed.
        server.withCString { cServer in
            apiKey.withCString { cAPIKey in
                username.withCString { cUsername in
                    password.withCString { cPassword in
                        logDir.withCString { cLogDir in
                            dataDir.withCString { cDataDir in
                                TCStart(UnsafeMutablePointer(mutating: cServer),
                                        UnsafeMutablePointer(mutating: cAPIKey),
                                        UnsafeMutablePointer(mutating: cUsername),
                                        UnsafeMutablePointer(mutating: cPassword),
                                        UnsafeMutablePointer(mutating: cLogDir),
                                        UnsafeMutablePointer(mutating: cDataDir)) == 0
                            }
                        }
                    }
                }
            }
        }
    }

    public static func stop() {
        TCStop()
    }

    public static func status() -> TunnelStatus? {
        guard let cStr = TCGetStatus() else { return nil }
        defer { TCFreeString(cStr) }
        let data = Data(String(cString: cStr).utf8)
        return try? JSONDecoder().decode(TunnelStatus.self, from: data)
    }

    public static func socksPort() -> Int32 {
        TCGetSocksPort()
    }

    public static func reconnect() {
        TCReconnect()
    }
}
