// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

// DefaultClientTelemetryKey is the ONE fleet-shared bearer key every new
// client build embeds for every client-facing telemetry endpoint (app-log,
// bananameter, log-upload, conn-stats) -- extractable from the binary, not a
// real secret boundary; per-device/per-user attribution is self-reported in
// each payload, same trust model each of these already had individually.
//
// Replaces the old one-key-per-endpoint scheme (2026-08-13): those keys were
// all baked into the same binary any real attacker already has, so
// per-endpoint separation added real operational cost (a deploy step per new
// feature -- missed twice: the log-upload-client-key incident, then
// conn-stats-client-key waiting on the exact identical fix before it ever
// shipped) for essentially no blast-radius reduction, since splitting keys
// doesn't change how many of them a binary-extraction attacker walks away
// with in one pass.
//
// The old per-endpoint constants are gone from client code (nothing outside
// this package referenced them by name), but the arbiter still accepts their
// VALUES indefinitely via each endpoint's legacy key config (see
// snc-arbiter/client_keys.go's checkClientOrLegacyKey) -- already-shipped
// client builds have the old keys baked in and can't be retroactively
// updated, so the server side must keep honoring them.
const DefaultClientTelemetryKey = "e30fd3acf2cc6318ab880494cd31f65bd5dca1409789c2a4"
