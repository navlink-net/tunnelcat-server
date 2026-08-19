// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"context"
	"net"
	"time"
)

// detectRegionByIP waits for the CIDR cache to load, looks up ip, and returns
// the ISO-3166 region code ("RU", "EU", …).
//
// Strategy:
//  1. CIDR lookup (waits up to 2 min for cache to populate)
//  2. Reverse-DNS TLD heuristic — fallback when IP is absent from CIDR data
//     (e.g. kk.fvds.ru → ".ru" → RU)
func detectRegionByIP(c *cidrCache, ip net.IP) string {
	// Wait for CIDR data.
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		c.mu.RLock()
		loaded := len(c.sets) > 0
		c.mu.RUnlock()
		if loaded {
			break
		}
		time.Sleep(3 * time.Second)
	}

	if cc := c.lookupCC(ip); cc != "" {
		logInfof("region: IP %s → %q (CIDR)", ip, cc)
		return cc
	}

	// Fallback: reverse-DNS TLD.
	if cc := regionFromReverseDNS(ip); cc != "" {
		logInfof("region: IP %s → %q (reverse-DNS TLD)", ip, cc)
		return cc
	}

	logWarnf("region: IP %s not in any known CIDR bucket and reverse-DNS gave no result — no region filter applied", ip)
	return ""
}

// regionFromReverseDNS resolves ip to a hostname and maps the TLD to a region.
// Returns "" if the lookup fails or the TLD is not recognised.
func regionFromReverseDNS(ip net.IP) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hosts, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(hosts) == 0 {
		return ""
	}
	// Use first returned hostname; strip trailing dot.
	host := hosts[0]
	if len(host) > 0 && host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}
	// Extract TLD (last label).
	tld := host
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == '.' {
			tld = host[i+1:]
			break
		}
	}

	tldMap := map[string]string{
		"ru": "RU", "su": "RU",
		"us": "US",
		"cn": "CN",
		"ir": "IR",
		// EU member-state ccTLDs.
		"de": "EU", "fr": "EU", "nl": "EU", "fi": "EU", "se": "EU",
		"pl": "EU", "it": "EU", "es": "EU", "be": "EU", "at": "EU",
		"cz": "EU", "hu": "EU", "ro": "EU", "bg": "EU", "hr": "EU",
		"si": "EU", "sk": "EU", "lt": "EU", "lv": "EU", "ee": "EU",
		"pt": "EU", "gr": "EU", "ie": "EU", "lu": "EU", "mt": "EU",
		"cy": "EU", "dk": "EU",
	}
	return tldMap[tld]
}
