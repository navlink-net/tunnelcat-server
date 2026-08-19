// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"

	"golang.org/x/crypto/ssh"
)

// loadOrGenArbiterSSHKey loads the arbiter's Ed25519 SSH private key from path,
// or generates a new one and saves it. The corresponding public key is installed
// in authorized_keys on every managed node during provisioning.
func loadOrGenArbiterSSHKey(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		if signer, err := ssh.ParsePrivateKey(data); err == nil {
			return signer, nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
