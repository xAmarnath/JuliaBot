package httpx

import (
	"fmt"
	"io"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

type Client = tls_client.HttpClient

func NewFirefox(timeout time.Duration, cookieJar bool) (Client, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Firefox_135),
		tls_client.WithTimeoutSeconds(int(timeout.Seconds())),
		tls_client.WithNotFollowRedirects(),
	}
	if cookieJar {
		opts = append(opts, tls_client.WithCookieJar(tls_client.NewCookieJar()))
	}
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, fmt.Errorf("tls client: %w", err)
	}
	return c, nil
}

func NewFirefoxFollowRedirects(timeout time.Duration, cookieJar bool) (Client, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Firefox_135),
		tls_client.WithTimeoutSeconds(int(timeout.Seconds())),
	}
	if cookieJar {
		opts = append(opts, tls_client.WithCookieJar(tls_client.NewCookieJar()))
	}
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, fmt.Errorf("tls client: %w", err)
	}
	return c, nil
}

func ReadAll(resp *fhttp.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
