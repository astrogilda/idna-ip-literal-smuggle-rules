// httpproxy_canonicalAddr_extracted.go
//
// Extraction of golang.org/x/net/http/httpproxy canonicalAddr
// (proxy.go::canonicalAddr) reduced to a buildable form for codemod
// regression testing. Upstream source:
//   golang.org/x/net v0.53.0, http/httpproxy/proxy.go
// See the function `canonicalAddr` and the helper `idnaASCII`.
//
// Vulnerability summary. `idnaASCII` invokes idna.Lookup.ToASCII(addr)
// and on success returns the mapped form. canonicalAddr feeds the
// result into net.JoinHostPort, and the result reaches the proxy
// connection logic. A hostname containing any of the UTS-46 NFKC fold
// codepoints (for example, the fullwidth digit one in "0.<FW1>.0.0")
// gets mapped to an ASCII IP literal ("0.1.0.0") which then reaches
// the network layer with no IP-literal recheck.
//
// This fixture uses a (string, error) return signature for idnaASCII
// (the real upstream function has the same shape). After the two-stage
// codemod runs:
//
//   Stage 1 (idna-add-post-recheck.patch): inserts the TrimRight +
//     netip.ParseAddr guard right after the ToASCII call.
//   Stage 2 (idna-add-sentinel.sh): injects the error sentinel var
//     at package scope so the guard compiles.
//
// The fixture does NOT pre-define the error sentinel variable, so
// stage 2 gets exercised end-to-end.

package httpproxy_extracted

import (
	"net"
	"net/url"

	"golang.org/x/net/idna"
)

// idnaASCII mirrors httpproxy/proxy.go::idnaASCII. Pure ASCII inputs
// short-circuit; everything else flows through idna.Lookup.ToASCII.
// The assignment form (out, err :=) is used here so that the Patch 1
// shape in idna-add-post-recheck.patch matches directly.
func idnaASCII(v string) (string, error) {
	for i := 0; i < len(v); i++ {
		if v[i] >= 0x80 {
			out, err := idna.Lookup.ToASCII(v)
			return out, err
		}
	}
	return v, nil
}

// canonicalAddr returns the host:port pair for the given URL, applying
// IDNA normalization. The function signature is (string, error) so the
// post-recheck guard inserted by stage 1 of the codemod compiles
// without a caller-signature change. The real upstream canonicalAddr
// returns a bare string; fixing that requires a one-line signature
// change which gopatch cannot synthesize.
func canonicalAddr(u *url.URL) (string, error) {
	addr := u.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return net.JoinHostPort(addr, port), nil
}
