package modules

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"net/http"
)

// Let's Encrypt's 2026 roots are missing from the heroku-24 CA bundle.
//
//go:embed certs/*.pem
var extraRootCAs embed.FS

func init() {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	entries, _ := extraRootCAs.ReadDir("certs")
	for _, e := range entries {
		if pem, err := extraRootCAs.ReadFile("certs/" + e.Name()); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{}
		}
		t.TLSClientConfig.RootCAs = pool
	}
}
