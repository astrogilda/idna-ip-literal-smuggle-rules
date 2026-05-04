package main

import (
	"net"
	"net/http"

	"golang.org/x/net/idna"
)

// VulnerableLookup illustrates the anti-pattern. The pre-IDNA net.ParseIP
// guard rejects non-ASCII inputs (it only accepts ASCII digits and dots),
// so the smuggled "0.¹.0.0" passes the guard, gets mapped by ToASCII to
// "0.1.0.0", and reaches http.Get as a routable IPv4 literal.
func VulnerableLookup(host string) (*http.Response, error) {
	// Pre-IDNA IP-literal guard. Looks defensive; isn't.
	if ip := net.ParseIP(host); ip != nil {
		return nil, errBadHost
	}

	// UTS-46 NFKC mapping folds 100 non-ASCII digit codepoints to ASCII.
	ace, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return nil, err
	}

	// No post-IDNA recheck: smuggled IP literals reach the network stack.
	return http.Get("https://" + ace + "/")
}

var errBadHost = errIPLiteral{}

type errIPLiteral struct{}

func (errIPLiteral) Error() string { return "ip literals not allowed" }
