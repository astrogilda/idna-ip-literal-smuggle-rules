// Negative test cases: compliant callers that must NOT trigger the alert.
// No `// $ Alert` annotations on the sink lines.

package main

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/idna"
)

// Compliant: post-IDNA TrimSuffix(".") followed by net.ParseIP recheck.
// This is the safe pattern.
func compliantTrimAndRecheck() {
	host := os.Getenv("HOST_OK_1") // $ Source
	ace, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return
	}
	candidate := strings.TrimSuffix(ace, ".")
	if ip := net.ParseIP(candidate); ip != nil {
		return
	}
	http.Get("https://" + ace + "/") // OK: post-IDNA recheck barrier
}

// Compliant variant: TrimRight(".") variant of the trim.
func compliantTrimRight() {
	host := os.Getenv("HOST_OK_2") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	candidate := strings.TrimRight(ace, ".")
	if ip := net.ParseIP(candidate); ip != nil {
		return
	}
	net.JoinHostPort(ace, "443") // OK
}

// True-negative: caller uses idna.Punycode, which does NOT apply the
// UTS-46 NFKC mapping. Even without a recheck, no digit-fold occurs.
func purePunycode() {
	host := os.Getenv("HOST_PUNYCODE") // $ Source
	ace, _ := idna.Punycode.ToASCII(host)
	http.Get("https://" + ace + "/") // OK: no digit-fold profile
}

// True-negative: caller uses idna.Display for human rendering only; the
// output never reaches a network sink in this function.
func displayOnly() {
	host := os.Getenv("HOST_DISPLAY") // $ Source
	disp, _ := idna.Display.ToUnicode(host)
	_ = disp // OK: never reaches a sink
}

// True-negative: pure URL-parser pipeline. net/url.Parse is not the
// IDNA mapper; URL.Host is consumed without idna.ToASCII having run.
func urlParseOnly() {
	raw := os.Getenv("URL_RAW") // $ Source
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	http.Get(u.String()) // OK: no IDNA mapping in the path
}

// True-negative: idna.ToASCII output is immediately discarded; nothing
// reaches a sink.
func idnaDiscard() {
	host := os.Getenv("HOST_DISCARD") // $ Source
	_, _ = idna.Lookup.ToASCII(host)  // OK: result discarded
}

// Compliant: post-IDNA TrimSuffix + net.ParseIP recheck before net.LookupHost.
func compliantLookupHost() {
	host := os.Getenv("HOST_LOOKUP_OK") // $ Source
	ace, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return
	}
	candidate := strings.TrimSuffix(ace, ".")
	if ip := net.ParseIP(candidate); ip != nil {
		return
	}
	net.LookupHost(ace) // OK: post-IDNA recheck barrier
}

// Compliant: post-IDNA TrimRight + net.ParseIP recheck before (*Resolver).LookupHost.
func compliantResolverLookupHost() {
	host := os.Getenv("HOST_RESOLVER_OK") // $ Source
	ace, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return
	}
	candidate := strings.TrimRight(ace, ".")
	if ip := net.ParseIP(candidate); ip != nil {
		return
	}
	r := &net.Resolver{}
	r.LookupHost(context.Background(), ace) // OK: post-IDNA recheck barrier
}

// Compliant: post-IDNA TrimSuffix + netip.ParseAddr recheck before (*Resolver).LookupIPAddr.
func compliantResolverLookupIPAddr() {
	host := os.Getenv("HOST_IPADDR_OK") // $ Source
	ace, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return
	}
	candidate := strings.TrimSuffix(ace, ".")
	if _, parseErr := netip.ParseAddr(candidate); parseErr == nil {
		return
	}
	r := &net.Resolver{}
	r.LookupIPAddr(context.Background(), ace) // OK: post-IDNA recheck barrier
}
