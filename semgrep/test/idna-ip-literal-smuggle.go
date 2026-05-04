// Test fixtures for idna-ip-literal-smuggle.
//
// Semgrep test layout: each `// ruleid: idna-ip-literal-smuggle` comment
// marks a positive match line; `// ok: idna-ip-literal-smuggle` marks a
// negative line. Run with `semgrep --test test/`.
//
// Coverage:
//   Positives:
//     P1  Latin-1 superscript fold (U+00B9)
//     P2  Math superscript fold (U+2074)
//     P3  Math subscript fold (U+2080)
//     P4  Circled digit fold (U+2460)
//     P5  Fullwidth digit fold (U+FF11)
//     P6  Math bold digit fold (U+1D7CE)
//     P7  Segmented digit fold (U+1FBF1)
//     P8  Trailing-dot bypass (no TrimSuffix)
//     P9  Tainted req.URL.Hostname() reaching net.Dial via ToASCII
//   Negatives:
//     N1  Compliant: TrimSuffix + netip.ParseAddr post-recheck
//     N2  Compliant: TrimSuffix + net.ParseIP post-recheck (legacy form)
//     N3  Compliant: idna.Punycode profile (no NFKC mapping)

package fixtures

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// ---------- Positives ----------

// P1: Latin-1 superscript ¹ (U+00B9) hardcoded literal -> ToASCII -> Dial.
func p1Latin1Superscript() {
	host := "0.¹.0.0" // ruleid: idna-ip-literal-smuggle
	ace, _ := idna.Lookup.ToASCII(host)
	_, _ = net.Dial("tcp", net.JoinHostPort(ace, "80")) // ruleid: idna-ip-literal-smuggle
}

// P2: Math superscript ⁴ (U+2074).
func p2MathSuperscript() {
	host := "0.⁴.0.0" // ruleid: idna-ip-literal-smuggle
	ace, _ := idna.Lookup.ToASCII(host)
	_, _ = http.Get("http://" + ace) // ruleid: idna-ip-literal-smuggle
}

// P3: Math subscript ₀ (U+2080).
func p3MathSubscript() {
	host := "0.₀.0.0" // ruleid: idna-ip-literal-smuggle
	profile := idna.New(idna.MapForLookup())
	ace, _ := profile.ToASCII(host)
	_, _ = net.LookupHost(ace) // ruleid: idna-ip-literal-smuggle
}

// P4: Circled digit ① (U+2460).
func p4CircledDigit() {
	host := "0.①.0.0" // ruleid: idna-ip-literal-smuggle
	ace, _ := idna.Lookup.ToASCII(host)
	req, _ := http.NewRequest("GET", "http://"+ace, nil) // ruleid: idna-ip-literal-smuggle
	_ = req
}

// P5: Fullwidth digit １ (U+FF11).
func p5FullwidthDigit() {
	host := "0.１.0.0" // ruleid: idna-ip-literal-smuggle
	ace, _ := idna.Lookup.ToASCII(host)
	u := &url.URL{Scheme: "http"}
	u.Host = ace // ruleid: idna-ip-literal-smuggle
}

// P6: Math bold digit (U+1D7CE).
func p6MathBoldDigit() {
	host := "0.\U0001D7CE.0.0" // ruleid: idna-ip-literal-smuggle
	ace, _ := idna.Lookup.ToASCII(host)
	c := &http.Cookie{}
	c.Domain = ace // ruleid: idna-ip-literal-smuggle
}

// P7: Segmented digit (U+1FBF1).
func p7SegmentedDigit() {
	host := "0.\U0001FBF1.0.0" // ruleid: idna-ip-literal-smuggle
	ace, _ := idna.Lookup.ToASCII(host)
	_, _ = net.DialTimeout("tcp", net.JoinHostPort(ace, "443"), 0) // ruleid: idna-ip-literal-smuggle
}

// P8: Trailing-dot bypass. Recheck is present, but no TrimSuffix.
// idna.Lookup.ToASCII("0.¹.0.0.") returns "0.1.0.0." which net.ParseIP
// rejects, so the recheck passes and the smuggled IP literal still
// reaches the sink.
func p8TrailingDotBypass(rawHost string) {
	ace, _ := idna.Lookup.ToASCII(rawHost)
	if net.ParseIP(ace) != nil { // recheck without prior TrimSuffix; defeated.
		return
	}
	_, _ = net.Dial("tcp", net.JoinHostPort(ace, "80")) // ruleid: idna-ip-literal-smuggle
}

// P9: Tainted request.URL.Hostname() -> ToASCII -> http.Client.Get.
func p9TaintedRequest(req *http.Request, c *http.Client) {
	host := req.URL.Hostname()
	ace, _ := idna.Lookup.ToASCII(host)
	_, _ = c.Get("http://" + ace) // ruleid: idna-ip-literal-smuggle
}

// ---------- Negatives ----------

// N1: Compliant. TrimSuffix(".") + netip.ParseAddr recheck.
func n1Compliant_NetipParseAddr(rawHost string) {
	ace, _ := idna.Lookup.ToASCII(rawHost)
	ace = strings.TrimSuffix(ace, ".")
	if _, err := netip.ParseAddr(ace); err == nil {
		return // reject: smuggled IP literal
	}
	// ok: idna-ip-literal-smuggle
	_, _ = net.Dial("tcp", net.JoinHostPort(ace, "80"))
}

// N2: Compliant. TrimSuffix(".") + net.ParseIP recheck (legacy form).
func n2Compliant_NetParseIP(rawHost string) {
	ace, _ := idna.Lookup.ToASCII(rawHost)
	ace = strings.TrimSuffix(ace, ".")
	if net.ParseIP(ace) != nil {
		return
	}
	// ok: idna-ip-literal-smuggle
	_, _ = http.Get("http://" + ace)
}

// N3: idna.Punycode profile. No NFKC mapping, no digit-fold surface.
func n3PunycodeProfile(rawHost string) {
	ace, _ := idna.Punycode.ToASCII(rawHost)
	// ok: idna-ip-literal-smuggle
	_, _ = net.Dial("tcp", net.JoinHostPort(ace, "80"))
}

// A fourth negative fixture (n4StrictNoIPLiteralOptIn) was removed.
// It exercised idna.StrictNoIPLiteral(), a proposed upstream Option
// that does not yet exist in any released golang.org/x/net/idna
// version, so the fixture would not compile against released x/net.
// When the upstream CL lands, restore the fixture and bump
// test.yaml::negatives back to 4.
