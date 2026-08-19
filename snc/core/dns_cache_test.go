// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// buildDNSResponse constructs a minimal wire-format DNS response with one
// A and one AAAA answer for the same name, mimicking what a real resolver
// sends when a client (e.g. Chrome/Android) queries both families for one
// host in parallel.
func buildDNSResponse(t *testing.T, name string, a [4]byte, aaaa [16]byte) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("Question: %v", err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatalf("StartAnswers: %v", err)
	}
	hdr := dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 300}
	if err := b.AResource(hdr, dnsmessage.AResource{A: a}); err != nil {
		t.Fatalf("AResource: %v", err)
	}
	if err := b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: aaaa}); err != nil {
		t.Fatalf("AAAAResource: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return msg
}

func TestGlobalDNSCacheLearnsIPv4ForHostFromAAAAQuery(t *testing.T) {
	c := &dnsCache{m: make(map[string]dnsCacheEntry), byHost: make(map[string]hostCacheEntry)}

	msg := buildDNSResponse(t, "ya.ru.", [4]byte{77, 88, 44, 242}, [16]byte{0x2a, 0x02, 0x06, 0xb8})
	c.ParseAndLearn(msg)

	if got := c.Get("2a02:6b8::"); got != "ya.ru." {
		t.Fatalf("Get(ipv6) = %q, want ya.ru.", got)
	}
	if got := c.GetIPv4ForHost("ya.ru."); got != "77.88.44.242" {
		t.Fatalf("GetIPv4ForHost(ya.ru.) = %q, want 77.88.44.242", got)
	}
	// Case-insensitivity, matching Set/Get's existing lowercasing behavior.
	if got := c.GetIPv4ForHost("YA.RU."); got != "77.88.44.242" {
		t.Fatalf("GetIPv4ForHost(YA.RU.) = %q, want 77.88.44.242", got)
	}
}

func TestGlobalDNSCacheGetIPv4ForHostMissOrExpired(t *testing.T) {
	c := &dnsCache{m: make(map[string]dnsCacheEntry), byHost: make(map[string]hostCacheEntry)}

	if got := c.GetIPv4ForHost("never-seen.example."); got != "" {
		t.Fatalf("GetIPv4ForHost(unseen) = %q, want empty", got)
	}

	c.setHost("expired.example.", "1.2.3.4", 5*time.Minute)
	c.mu.Lock()
	c.byHost["expired.example."] = hostCacheEntry{ipv4: "1.2.3.4", expires: time.Now().Add(-time.Second)}
	c.mu.Unlock()
	if got := c.GetIPv4ForHost("expired.example."); got != "" {
		t.Fatalf("GetIPv4ForHost(expired) = %q, want empty", got)
	}
}
