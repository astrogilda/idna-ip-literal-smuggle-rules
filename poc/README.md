# Proof of concept: UTS-46 IDNA IP-literal smuggling via `golang.org/x/net/http/httpproxy`

A self-contained Go program that exercises the bug class against a recent
released `golang.org/x/net`. The program builds an `httpproxy.Config` with
`NoProxy: "0.1.0.0"`, then runs four URLs through the resulting `ProxyFunc`.
The fullwidth and mathematical-superscript URLs canonicalise to `"0.1.0.0"`
post-IDNA, match the `NoProxy` entry, and bypass the operator's proxy.

## Run

```bash
mkdir poc && cd poc
go mod init poc
cat > go.mod <<'EOF'
module poc

go 1.22

require golang.org/x/net v0.53.0
EOF
go mod tidy
cp ../httpproxy_idna_smuggle.go .
go run httpproxy_idna_smuggle.go
```

Expected output: the fullwidth and superscript URLs return `proxy=<nil>`
(i.e. "do not use a proxy") while `https://example.com/api` correctly returns
the configured corporate proxy URL. That is the bypass.

## Threat model

`NoProxy` policy bypass is a real exploit surface for any deployment that
uses HTTP-proxy-based egress monitoring or DLP. End-to-end SSRF through the
stdlib pipeline does not work: `net.LookupHost` rejects the canonicalised
literal with `no such host` (the resolver will not look up `0.1.0.0` as a
hostname). The proxy-routing decision happens before that lookup, though,
so the bypass is real for the proxy-routing surface specifically.

## Scope

This PoC targets only `golang.org/x/net/http/httpproxy`. The Semgrep, CodeQL,
and gopatch artefacts in the parent directory cover the broader bug class:
any caller that calls `idna.ToASCII` and then dials, sets a TLS SNI, sets a
cookie domain, or hits a DNS resolver without rechecking the post-mapping
result.
