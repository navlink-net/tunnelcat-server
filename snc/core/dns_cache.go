// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// GlobalDNSCache maps resolved IP addresses to their FQDN so ShouldBypass can
// apply TLD-based routing overrides (e.g. .ru → always tunnel for non-RU users).
// It also keeps the reverse direction (FQDN → last-seen IPv4) so a blocked
// IPv6 dial can transparently substitute the IPv4 address of the same host
// instead of failing outright — see ipv4ForBlockedIPv6's doc comment in
// android-core/tun_dialer_linux.go for why this can't be solved by simply
// letting the OS/browser's own Happy Eyeballs retry on IPv4.
var GlobalDNSCache = &dnsCache{
	m:      make(map[string]dnsCacheEntry),
	byHost: make(map[string]hostCacheEntry),
}

type dnsCache struct {
	mu       sync.RWMutex
	m        map[string]dnsCacheEntry
	byHost   map[string]hostCacheEntry
	initOnce sync.Once
}

type dnsCacheEntry struct {
	fqdn    string
	expires time.Time
}

type hostCacheEntry struct {
	ipv4    string
	expires time.Time
}

func (c *dnsCache) startCleanup() {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			c.mu.Lock()
			for ip, e := range c.m {
				if now.After(e.expires) {
					delete(c.m, ip)
				}
			}
			for host, e := range c.byHost {
				if now.After(e.expires) {
					delete(c.byHost, host)
				}
			}
			c.mu.Unlock()
		}
	}()
}

// Set stores an IP→FQDN mapping, capping TTL between 5 min and 24 h.
func (c *dnsCache) Set(ip, fqdn string, ttl time.Duration) {
	c.initOnce.Do(c.startCleanup)
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	c.mu.Lock()
	c.m[ip] = dnsCacheEntry{fqdn: strings.ToLower(fqdn), expires: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// Get returns the FQDN for ip, or "" if not cached or expired.
func (c *dnsCache) Get(ip string) string {
	c.mu.RLock()
	e, ok := c.m[ip]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return ""
	}
	return e.fqdn
}

// setHost records fqdn's last-seen IPv4 address, capping TTL the same way Set does.
func (c *dnsCache) setHost(fqdn, ipv4 string, ttl time.Duration) {
	c.initOnce.Do(c.startCleanup)
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	c.mu.Lock()
	c.byHost[strings.ToLower(fqdn)] = hostCacheEntry{ipv4: ipv4, expires: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// GetIPv4ForHost returns fqdn's last-seen IPv4 address, or "" if none is cached
// or it expired.
func (c *dnsCache) GetIPv4ForHost(fqdn string) string {
	c.mu.RLock()
	e, ok := c.byHost[strings.ToLower(fqdn)]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return ""
	}
	return e.ipv4
}

// DescribeQuestion returns "name TYPE" for the first question in a DNS
// wire-format query, or "" if it can't be parsed. Debug-only helper for
// logging exactly which record type a client asked for (A vs AAAA) — see
// the investigation note in android-core/tun_dialer_linux.go about ya.ru
// sometimes never getting an IPv4 substitute.
func DescribeQuestion(msg []byte) string {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return ""
	}
	q, err := p.Question()
	if err != nil {
		return ""
	}
	return q.Name.String() + " " + q.Type.String()
}

// ParseAndLearn extracts A/AAAA records from a DNS wire-format response and
// populates the cache. Silently ignores malformed messages.
func (c *dnsCache) ParseAndLearn(msg []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		ttl := time.Duration(h.TTL) * time.Second
		fqdn := h.Name.String()
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return
			}
			ip := net.IP(r.A[:]).String()
			c.Set(ip, fqdn, ttl)
			c.setHost(fqdn, ip, ttl)
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return
			}
			c.Set(net.IP(r.AAAA[:]).String(), fqdn, ttl)
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
		}
	}
}
