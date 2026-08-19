// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// runKeygen implements the "snc-arbiter keygen" subcommand.
// It generates an Ed25519 key pair, writes the private key to --sign-key path,
// and prints the public key hex to stdout so it can be passed to snc-control/snc-exit
// at build time via --pubkey.
func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyPath := fs.String("sign-key", defaultSignKey(), "output path for Ed25519 private key PEM")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: snc-arbiter keygen [--sign-key PATH]

Generates an Ed25519 signing key pair for the arbiter.

  --sign-key PATH   where to write the private key PEM (default: %s)

The private key is saved to PATH.
The public key hex is printed to stdout — pass it to snc-control/snc-exit
via the --pubkey flag so they can verify signed node lists.

Typical workflow:
  1. snc-arbiter keygen --sign-key /var/lib/snc/arbiter.ed25519
  2. Copy the printed pubkey hex.
  3. Start snc-control with --pubkey <hex>
  4. Start snc-arbiter with --sign-key /var/lib/snc/arbiter.ed25519
`, defaultSignKey())
	}
	fs.Parse(args)

	if err := os.MkdirAll(filepath.Dir(*keyPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error: mkdir %s: %v\n", filepath.Dir(*keyPath), err)
		os.Exit(1)
	}

	// Refuse to overwrite an existing key without explicit confirmation.
	if _, err := os.Stat(*keyPath); err == nil {
		fmt.Fprintf(os.Stderr, "error: %s already exists — delete it first if you want a new key\n", *keyPath)
		os.Exit(1)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: generate key: %v\n", err)
		os.Exit(1)
	}

	f, err := os.OpenFile(*keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: write key: %v\n", err)
		os.Exit(1)
	}
	if err := pem.Encode(f, &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: []byte(priv), // raw 64 bytes: seed || pubkey
	}); err != nil {
		f.Close()
		fmt.Fprintf(os.Stderr, "error: encode PEM: %v\n", err)
		os.Exit(1)
	}
	f.Close()

	fmt.Fprintf(os.Stderr, "Private key written to: %s\n", *keyPath)
	fmt.Fprintf(os.Stderr, "\nPublic key (pass to snc-control/snc-exit via --pubkey):\n")
	fmt.Printf("%x\n", pub)
}
