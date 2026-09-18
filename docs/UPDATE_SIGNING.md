# OTA update signing

Every client build verifies a downloaded update's Ed25519 signature (see
`snc/core/update_sig.go`) before applying it, in addition to the SHA-256
integrity check that already existed. This closes a real gap: control nodes
are addressed by IP with self-signed certs (`InsecureSkipVerify` throughout
`snc/core/updater*.go`, by design — see those files' doc comments), and the
SHA-256 sidecar used to be fetched over that same unauthenticated channel.
Without a signature, anyone who can serve traffic on that path — an on-path
network attacker, or a compromised/malicious control node — could serve an
arbitrary binary that a client would download, "verify" against an
attacker-supplied hash, and execute with the running client's own
privileges.

## How it works

1. `snc-arbiter`'s upload handler (`admin_downloads.go`) signs
   `slug|version|sha256hex` with an Ed25519 private key at upload time and
   writes the result as `<canonicalName>.sig` next to the existing
   `.sha256`/`.version` sidecars.
2. Control nodes cache and serve `.sig` the same way they already cache and
   serve `.sha256`/`.version` (`snc-control/client_cache.go`,
   `update_http.go`) — no protocol change beyond one more file extension.
3. Every client (`snc/core/updater.go`, `updater_darwin.go`,
   `updater_linux.go`) fetches the `.sig` sidecar alongside `.sha256` and
   calls `core.VerifyUpdateSig(slug, version, sha256hex, sig)` against the
   public key baked into the binary at build time
   (`core.UpdateSigningPubKeyHex`) before ever extracting or executing the
   downloaded update. A missing or invalid signature is treated exactly
   like a SHA-256 mismatch: the update is rejected and the client tries the
   next control.

## Generating a keypair (official navlink.net fleet, or your own fork)

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Println("PUB: " + hex.EncodeToString(pub))   // -> core.UpdateSigningPubKeyHex
	fmt.Println("PRIV:" + hex.EncodeToString(priv))  // -> --update-signing-key, keep secret
}
```

- The **public** key is not a secret — put it directly in
  `snc/core/update_sig.go`'s `UpdateSigningPubKeyHex` constant and rebuild
  every client. This is exactly why it's a plain source constant rather
  than a build-time `-ldflags -X` value like `Version`: every client needs
  the *same* verify key regardless of which machine built it.
- The **private** key must never be committed anywhere. Pass it to
  `snc-arbiter` via `--update-signing-key <hex>` or, better,
  `--update-signing-key-file <path>` (keeps it out of the process list and
  shell history). If you run a multi-node arbiter cluster
  (see `--peer-arbiters`), every node needs the *same* private key —
  whichever node happens to handle a given upload is the one that signs it.
- If self-hosting your own fork of this project: generate your own keypair
  and replace `UpdateSigningPubKeyHex` with your own public key before
  building clients. A client built against the official navlink.net public
  key will never accept updates signed by your fork's key, and vice versa
  — there's no shared trust between independently-run fleets, by design.

## `--update-signing-key` is effectively required once clients are rebuilt

`VerifyUpdateSig` fails closed: a missing, empty, or malformed `.sig`
verifies as `false`, exactly like a SHA-256 mismatch. There is no
backward-compatible "unsigned is OK" path, and deliberately so — an
"accept if the sidecar is just absent" exception would let an attacker
reproduce the original vulnerability trivially, by serving no `.sig` at
all instead of a wrong one.

Concretely, this means:

- **Old clients** (built before this feature shipped, with no
  `VerifyUpdateSig` call at all) are completely unaffected — they keep
  doing the pre-2026-09-18 SHA-256-only check and update normally, signed
  or not. No compatibility concern there.
- **New clients** (built with this code, carrying `UpdateSigningPubKeyHex`)
  will **reject every update and never self-update again** the moment
  `snc-arbiter` is run without `--update-signing-key` /
  `--update-signing-key-file` configured — `admin_downloads.go` logs a
  warning on every affected upload precisely because this is a real outage
  for any already-rebuilt client, not just a theoretical weakening.

So: configure `--update-signing-key`/`--update-signing-key-file` on every
arbiter cluster node *before* or *at the same time as* rolling out the
first client build that includes this feature. Configuring it after the
fact still works (clients simply start succeeding again on their next
check), but there is no safe order to defer it in once new clients are
already out.
