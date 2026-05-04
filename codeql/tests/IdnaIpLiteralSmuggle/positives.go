// Positive test cases for the IDNA digit-fold IP-literal smuggle query.
// Each `// $ Source` and `// $ Alert` annotation is consumed by the
// CodeQL InlineExpectationsTestQuery harness.
//
// The smuggle inputs are illustrative string constants; in real-world
// callers the value would arrive via an ActiveThreatModelSource (HTTP
// header, env, file). To exercise the source classifier in tests we
// pipe each through `os.Getenv`, which is one of the standard
// threat-model sources in the Go CodeQL library.

package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/net/idna"
)

// --- Class 1: Latin-1 superscripts (U+00B9 SUPERSCRIPT ONE) ---
// "0.¹.0.0" -> "0.1.0.0"
func smuggleLatin1Superscript() {
	host := os.Getenv("HOST_LATIN1") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	http.Get("https://" + ace + "/") // $ Alert
}

// --- Class 2: Mathematical superscripts (U+2074 SUPERSCRIPT FOUR) ---
// "10.⁴.0.1" -> "10.4.0.1"
func smuggleMathSuperscript() {
	host := os.Getenv("HOST_MATHSUP") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	net.JoinHostPort(ace, "443") // $ Alert
}

// --- Class 3: Mathematical subscripts (U+2081 SUBSCRIPT ONE) ---
// "127.0.0.₁" -> "127.0.0.1"
func smuggleMathSubscript() {
	host := os.Getenv("HOST_SUBSCRIPT") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	cfg := &tls.Config{}
	cfg.ServerName = ace // $ Alert
	_ = cfg
}

// --- Class 4: Circled digits (U+2460 CIRCLED DIGIT ONE) ---
// "192.168.①.1" -> "192.168.1.1"
func smuggleCircledDigit() {
	host := os.Getenv("HOST_CIRCLED") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	net.Dial("tcp", net.JoinHostPort(ace, "80")) // $ Alert
}

// --- Class 5: Fullwidth digits (U+FF11 FULLWIDTH DIGIT ONE) ---
// "１９２.１６８.１.１" -> "192.168.1.1"
func smuggleFullwidth() {
	host := os.Getenv("HOST_FULLWIDTH") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	c := &http.Cookie{}
	c.Domain = ace // $ Alert
	_ = c
}

// --- Class 6: Mathematical bold/sans/double-struck/mono (U+1D7CE MATH BOLD ZERO) ---
// "\U0001D7CE.\U0001D7CF.\U0001D7CE.\U0001D7CF" -> "0.1.0.1"
func smuggleMathBold() {
	host := os.Getenv("HOST_MATHBOLD") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	u := &url.URL{Scheme: "https"}
	u.Host = ace // $ Alert
	_ = u
}

// --- Class 7: Segmented digits (U+1FBF1 SEGMENTED DIGIT ONE) ---
// "\U0001FBF1.0.0.0" -> "1.0.0.0"
func smuggleSegmented() {
	host := os.Getenv("HOST_SEGMENTED") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	http.Get("https://" + ace + "/") // $ Alert
}

// --- Class 8: U+24EA CIRCLED DIGIT ZERO (the only zero-circled,
// in the same circled family but worth a dedicated case because
// U+2460 starts at one) ---
// "⓪.0.0.1" -> "0.0.0.1"
func smuggleCircledZero() {
	host := os.Getenv("HOST_CIRCLED_ZERO") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	http.Get("https://" + ace + "/") // $ Alert
}

// --- Trailing-dot variant: "0.¹.0.0." -> "0.1.0.0." ---
// A bare `net.ParseIP("0.1.0.0.")` returns nil, so a post-IDNA recheck
// WITHOUT a trailing-dot trim does NOT sanitize. The query must still
// alert here.
func smuggleTrailingDot() {
	host := os.Getenv("HOST_TRAILING_DOT") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	if ip := net.ParseIP(ace); ip != nil { // wrong: no TrimSuffix
		return
	}
	http.Get("https://" + ace + "/") // $ Alert
}

// --- DNS resolver sinks ---

// net.LookupHost: smuggled IP literal triggers DNS query for the literal form.
// "0.¹.0.0" -> "0.1.0.0"; LookupHost("0.1.0.0") issues a PTR-style query that
// some resolvers answer with the IP directly.
func smuggleLookupHost() {
	host := os.Getenv("HOST_LOOKUP") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	net.LookupHost(ace) // $ Alert
}

// net.LookupIP: same digit-fold as above; argument 0 is the host.
func smuggleLookupIP() {
	host := os.Getenv("HOST_LOOKUP_IP") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	net.LookupIP(ace) // $ Alert
}

// (*net.Resolver).LookupHost: custom resolver; host is argument 1, ctx is argument 0.
func smuggleResolverLookupHost() {
	host := os.Getenv("HOST_RESOLVER_LOOKUP") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	r := &net.Resolver{}
	r.LookupHost(context.Background(), ace) // $ Alert
}

// (*net.Resolver).LookupIPAddr: custom resolver; host is argument 1.
func smuggleResolverLookupIPAddr() {
	host := os.Getenv("HOST_RESOLVER_IPADDR") // $ Source
	ace, _ := idna.Lookup.ToASCII(host)
	r := &net.Resolver{}
	r.LookupIPAddr(context.Background(), ace) // $ Alert
}

// --- Caller-pattern reproduction: pre-IDNA ParseIP guard, no post-IDNA
// recheck. Mirrors `golang.org/x/net/http/httpproxy/proxy.go::canonicalAddr`. ---
func smuggleCanonicalAddrShape() {
	addr := os.Getenv("HOST_CANONICAL") // $ Source
	if ip := net.ParseIP(addr); ip != nil {
		// pretend we reject IP-literal inputs early
		return
	}
	if v, err := idna.Lookup.ToASCII(addr); err == nil {
		addr = v
	}
	net.JoinHostPort(addr, "443") // $ Alert
}
