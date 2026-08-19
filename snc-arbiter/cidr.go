// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// cidrPayload is the signed CIDR list for a single country.
type cidrPayload struct {
	Country string   `json:"country"`
	TS      int64    `json:"ts"`
	CIDRs   []string `json:"cidrs"`
	Sig     string   `json:"sig"` // base64url Ed25519 over {country,ts,cidrs}
}

// allCountriesPayload is the multi-country wire format returned by GET /api/cidr/all.
type allCountriesPayload struct {
	TS        int64                      `json:"ts"`
	Countries map[string]json.RawMessage `json:"countries"`
}

// cidrProvider holds a CIDR list in memory.
type cidrProvider struct {
	country string
	cidrs   []string
}

func newCIDRProvider(country string, cidrs []string) *cidrProvider {
	return &cidrProvider{country: country, cidrs: cidrs}
}

// ── ipdeny.com download ───────────────────────────────────────────────────────

// ipdenyURL returns the ipdeny.com aggregated IPv4 zone file URL for a country code.
func ipdenyURL(cc string) string {
	return "https://www.ipdeny.com/ipblocks/data/aggregated/" +
		strings.ToLower(cc) + "-aggregated.zone"
}

// ipdenyIPv6URL returns the ipdeny.com aggregated IPv6 zone file URL for a country code.
func ipdenyIPv6URL(cc string) string {
	return "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/" +
		strings.ToLower(cc) + "-aggregated.zone"
}

// singleCountries are fetched individually from ipdeny.com.
var singleCountries = []string{"RU", "US", "CN", "IR"}

// euMembers are EU member states aggregated into one "EU" bucket.
var euMembers = []string{
	"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR",
	"GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL",
	"PT", "RO", "SE", "SI", "SK",
}

// supplementalASNs lists ASNs whose currently-announced prefixes are merged
// into a country's CIDR bucket in addition to ipdeny's aggregation.
// ipdeny's free country zone files are derived from RIR registration data,
// which misses major providers whose address space isn't registered under
// that country even though the service is unambiguously hosted/operated
// there. Confirmed for Yandex (AS13238): ipdeny's ru-aggregated.zone does
// not include 213.180.192.0/19 (ip.yandex.ru's own range) -- this broke both
// exit-region classification (an exit physically hosted on Yandex Cloud
// CIDR-detecting as unknown) and target-country geo-routing (yandex.ru
// itself resolving to "unknown" country, so snc-exit's geo-peer redirect
// never even attempted to find a RU peer). Add more entries here as similar
// gaps are found for other major Russian services.
var supplementalASNs = map[string][]string{
	"RU": {"13238"}, // Yandex LLC
}

// fetchASNPrefixes fetches AS<asn>'s currently-announced IPv4/IPv6 prefixes
// from RIPEstat's public API (no auth, no rate-limit issues observed for
// this call volume -- one lookup per ASN per hourly refresh cycle).
func fetchASNPrefixes(asn string) ([]string, error) {
	url := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + asn
	resp, err := http.Get(url) //nolint:gosec,noctx // public RIPEstat data, no sensitive context
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var payload struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode RIPEstat response for AS%s: %w", asn, err)
	}
	out := make([]string, 0, len(payload.Data.Prefixes))
	for _, p := range payload.Data.Prefixes {
		out = append(out, p.Prefix)
	}
	return out, nil
}

// downloadLines fetches a URL and returns non-empty, non-comment lines.
func downloadLines(url string) ([]string, error) {
	resp, err := http.Get(url) //nolint:gosec,noctx // public RIR data, no sensitive context
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var lines []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

// fetchCountry downloads IPv4 and IPv6 CIDRs for a single country code from ipdeny.com.
func fetchCountry(cc string) (*cidrProvider, error) {
	v4, err := downloadLines(ipdenyURL(cc))
	if err != nil {
		return nil, err
	}
	v6, err := downloadLines(ipdenyIPv6URL(cc))
	if err != nil {
		logWarnf("cidr: IPv6 fetch skipped for %s: %v", cc, err)
	}
	all := append(v4, v6...)
	logInfof("cidr: downloaded %d CIDRs for %s (v4=%d v6=%d)", len(all), cc, len(v4), len(v6))
	for _, asn := range supplementalASNs[cc] {
		extra, err := fetchASNPrefixes(asn)
		if err != nil {
			logWarnf("cidr: supplemental AS%s fetch failed for %s: %v", asn, cc, err)
			continue
		}
		all = append(all, extra...)
		logInfof("cidr: supplemented %s with %d prefixes from AS%s", cc, len(extra), asn)
	}
	return newCIDRProvider(cc, all), nil
}

// fetchEU downloads and aggregates IPv4 and IPv6 CIDRs for all EU member states.
func fetchEU() (*cidrProvider, error) {
	var all []string
	for _, cc := range euMembers {
		v4, err := downloadLines(ipdenyURL(cc))
		if err != nil {
			logWarnf("cidr: EU: skip v4 %s: %v", cc, err)
		} else {
			all = append(all, v4...)
		}
		v6, err := downloadLines(ipdenyIPv6URL(cc))
		if err != nil {
			logWarnf("cidr: EU: skip v6 %s: %v", cc, err)
		} else {
			all = append(all, v6...)
		}
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no EU CIDRs fetched")
	}
	logInfof("cidr: downloaded %d CIDRs for EU (%d member states)", len(all), len(euMembers))
	return newCIDRProvider("EU", all), nil
}

// FetchAllCIDRs downloads CIDR lists for RU, US, CN, IR, and EU.
// On partial failure the successful countries are still returned; the error
// contains a summary of which fetches failed.
func FetchAllCIDRs() (map[string]*cidrProvider, error) {
	type result struct {
		p   *cidrProvider
		err error
	}

	// All fetches in parallel.
	chs := make(map[string]chan result, len(singleCountries)+1)
	for _, cc := range singleCountries {
		cc := cc
		ch := make(chan result, 1)
		chs[cc] = ch
		go func() { p, err := fetchCountry(cc); ch <- result{p, err} }()
	}
	euCh := make(chan result, 1)
	go func() { p, err := fetchEU(); euCh <- result{p, err} }()

	providers := make(map[string]*cidrProvider)
	var errs []string

	for cc, ch := range chs {
		r := <-ch
		if r.err != nil {
			logWarnf("cidr: fetch %s: %v", cc, r.err)
			errs = append(errs, cc)
		} else {
			providers[cc] = r.p
		}
	}
	if r := <-euCh; r.err != nil {
		logWarnf("cidr: fetch EU: %v", r.err)
		errs = append(errs, "EU")
	} else {
		providers["EU"] = r.p
	}

	if len(providers) == 0 {
		return nil, fmt.Errorf("all CIDR fetches failed: %s", strings.Join(errs, ", "))
	}
	var err error
	if len(errs) > 0 {
		err = fmt.Errorf("some countries failed: %s", strings.Join(errs, ", "))
	}
	return providers, err
}

// ── background refresher ──────────────────────────────────────────────────────

// StartCIDRRefresher launches a goroutine that calls FetchAllCIDRs immediately
// and then every interval, updating the handler's CIDR providers each time.
// If the initial fetch fails, retries every retryInterval until it succeeds.
func StartCIDRRefresher(h *handler, interval time.Duration) {
	const retryInterval = 10 * time.Minute
	go func() {
		logInfof("cidr refresher: starting (interval=%s, retry=%s)", interval, retryInterval)
		refresh := func() bool {
			logInfof("cidr refresher: fetching CIDR lists from ipdeny.com…")
			providers, err := FetchAllCIDRs()
			if err != nil {
				logWarnf("cidr refresher: fetch error: %v", err)
			}
			if len(providers) > 0 {
				h.setCIDRs(providers)
				logInfof("cidr refresher: updated %d country buckets: %v", len(providers), cidrKeys(providers))
				return true
			}
			logWarnf("cidr refresher: no providers loaded — CIDR-based geo-filtering disabled")
			return false
		}

		// Retry until the first successful load.
		for !refresh() {
			logWarnf("cidr refresher: initial fetch failed, retrying in %s", retryInterval)
			time.Sleep(retryInterval)
		}

		// Periodic refresh.
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			refresh()
		}
	}()
}

// cidrKeys returns a sorted list of country codes present in the providers map.
func cidrKeys(m map[string]*cidrProvider) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ── signing ───────────────────────────────────────────────────────────────────

// signCIDRs builds and signs a cidrPayload for a single country.
func (s *signingKey) signCIDRs(country string, cidrs []string) ([]byte, error) {
	ts := time.Now().Unix()

	payload := struct {
		Country string   `json:"country"`
		TS      int64    `json:"ts"`
		CIDRs   []string `json:"cidrs"`
	}{Country: country, TS: ts, CIDRs: cidrs}

	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)

	out := cidrPayload{
		Country: country,
		TS:      ts,
		CIDRs:   cidrs,
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.Marshal(out)
}

// signAllCountries signs each country's list individually and returns a
// combined allCountriesPayload.  Protected by a read-lock on the handler.
func (s *signingKey) signAllCountries(providers map[string]*cidrProvider) ([]byte, error) {
	countries := make(map[string]json.RawMessage, len(providers))
	for cc, p := range providers {
		data, err := s.signCIDRs(cc, p.cidrs)
		if err != nil {
			return nil, fmt.Errorf("sign %s: %w", cc, err)
		}
		countries[cc] = json.RawMessage(data)
	}
	out := allCountriesPayload{
		TS:        time.Now().Unix(),
		Countries: countries,
	}
	return json.Marshal(out)
}

// ── thread-safe provider map on handler ──────────────────────────────────────

// cidrState is the mutex-protected CIDR provider map stored on the handler.
// It also maintains pre-parsed *net.IPNet slices for fast IP → region lookup.
type cidrState struct {
	mu        sync.RWMutex
	providers map[string]*cidrProvider
	nets      map[string][]*net.IPNet // country → parsed CIDR set
}

func (cs *cidrState) set(providers map[string]*cidrProvider) {
	nets := make(map[string][]*net.IPNet, len(providers))
	for cc, p := range providers {
		var ns []*net.IPNet
		for _, c := range p.cidrs {
			_, n, err := net.ParseCIDR(c)
			if err == nil {
				ns = append(ns, n)
			}
		}
		nets[cc] = ns
	}
	cs.mu.Lock()
	cs.providers = providers
	cs.nets = nets
	cs.mu.Unlock()
}

func (cs *cidrState) get() map[string]*cidrProvider {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.providers
}

// knownRegions returns a sorted list of country codes that have CIDR data loaded.
func (cs *cidrState) knownRegions() []string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	out := make([]string, 0, len(cs.nets))
	for cc := range cs.nets {
		out = append(out, cc)
	}
	sort.Strings(out)
	return out
}

// lookupIP returns the region code for ip, or "" if no bucket matches.
func (cs *cidrState) lookupIP(ip net.IP) string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	for cc, ns := range cs.nets {
		for _, n := range ns {
			if n.Contains(ip) {
				return cc
			}
		}
	}
	return ""
}
