package extras

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPasteProviders(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	content := "  hello <world>\n\tTamil: தமிழ்\n"
	for _, svc := range pasteServices {
		t.Run(svc.id, func(t *testing.T) {
			http.DefaultTransport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "POST" {
					t.Fatal(r.Method)
				}
				resp := &http.Response{StatusCode: 201, Header: make(http.Header), Request: r}
				body := ""
				switch svc.id {
				case "katbin":
					var payload map[string]map[string]string
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload["paste"]["content"] != content {
						t.Fatalf("lost paste content: %v", err)
					}
					body = `{"id":"abc123"}`
				case "dpaste":
					if err := r.ParseForm(); err != nil || r.Form.Get("content") != content || r.Form.Get("expiry_days") != "7" {
						t.Fatalf("wrong dpaste form: %v", err)
					}
					body = "https://dpaste.com/ABC123\n"
				case "spacebin":
					if err := r.ParseMultipartForm(1 << 20); err != nil || r.FormValue("content") != content {
						t.Fatalf("wrong spacebin form: %v", err)
					}
					resp.StatusCode = 301
					resp.Header.Set("Location", "/abc123")
				case "pastesdev":
					if b, _ := io.ReadAll(r.Body); string(b) != content {
						t.Fatal("wrong pastes.dev body")
					}
					body = `{"key":"abc123"}`
				case "pasters":
					if b, _ := io.ReadAll(r.Body); string(b) != content {
						t.Fatal("wrong paste.rs body")
					}
					body = "https://paste.rs/abc123"
				}
				resp.Body = io.NopCloser(strings.NewReader(body))
				return resp, nil
			})
			link, err := svc.upload(context.Background(), content)
			if err != nil || !strings.HasPrefix(link, "https://"+svc.name+"/") {
				t.Fatalf("%q %v", link, err)
			}
			http.DefaultTransport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 503, Header: http.Header{"Location": []string{"https://evil.test/error"}}, Body: io.NopCloser(strings.NewReader("unavailable")), Request: r}, nil
			})
			if _, err := svc.upload(context.Background(), content); err == nil {
				t.Fatal("accepted provider failure as a paste")
			}
		})
	}
}

func TestPasteTextEncoding(t *testing.T) {
	for _, test := range []struct {
		input []byte
		want  string
	}{
		{[]byte("  line\r\n\tதமிழ்\n"), "  line\r\n\tதமிழ்\n"},
		{[]byte{0xef, 0xbb, 0xbf, 'x'}, "x"},
		{[]byte{0xff, 0xfe, 'x', 0, '\n', 0}, "x\n"},
		{[]byte{0xfe, 0xff, 0, 'x', 0xd8, 0x3d, 0xde, 0x00}, "x😀"},
	} {
		got, err := pasteDecodeText(test.input)
		if err != nil || got != test.want {
			t.Fatalf("%q %v", got, err)
		}
	}
	for _, data := range [][]byte{{0xff}, {'x', 0, 'y'}, {0xff, 0xfe, 'x'}} {
		got, err := pasteDecodeText(data)
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Binary file (base64):\n"))
		if err != nil || decodeErr != nil || !bytes.Equal(decoded, data) {
			t.Fatal("binary contents changed")
		}
	}
	if _, err := pasteDecodeText(bytes.Repeat([]byte{'x'}, int(pasteMaxDocBytes)+1)); err == nil {
		t.Fatal("file larger than 2 MiB accepted")
	}
	if _, err := pasteDecodeText(bytes.Repeat([]byte{0xff}, int(pasteMaxDocBytes))); err != nil {
		t.Fatal("2 MiB binary file rejected", err)
	}
}

func TestPasteFallbackOrderAndURLs(t *testing.T) {
	for _, preferred := range []string{"", "katbin", "dpaste", "spacebin", "pastesdev", "pasters", "unknown"} {
		ordered := pasteOrderedServices(preferred)
		if len(ordered) != len(pasteServices) {
			t.Fatal(ordered)
		}
		seen := map[string]bool{}
		for _, svc := range ordered {
			if seen[svc.id] {
				t.Fatal("duplicate provider")
			}
			seen[svc.id] = true
		}
		if seen[preferred] && ordered[0].id != preferred {
			t.Fatal("preferred provider not first")
		}
	}
	for _, raw := range []string{"javascript:alert(1)", "https://dpaste.com.evil.test/id", "https://dpaste.com/", "https://user@dpaste.com/id", "http://dpaste.com/id"} {
		if _, err := pasteValidatedURL(raw, "dpaste.com"); err == nil {
			t.Fatal(raw)
		}
	}
}

func TestPasteServicesLive(t *testing.T) {
	if os.Getenv("PASTE_LIVE") == "" {
		t.Skip("set PASTE_LIVE=1 to hit the real paste services")
	}
	content := fmt.Sprintf("jb paste live check %d\nline two ✓", time.Now().UnixNano())
	for _, svc := range pasteServices {
		t.Run(svc.id, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			link, err := svc.upload(ctx, content)
			if err != nil {
				t.Fatalf("upload: %v", err)
			}
			raw := pasteRawURL(link, svc.id)
			if raw == "" {
				t.Fatalf("no raw url for %s", link)
			}
			resp, err := pasteClient.Get(raw)
			if err != nil {
				t.Fatalf("fetch raw: %v", err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if strings.TrimSpace(string(got)) != content {
				t.Fatalf("raw %s returned %q", raw, got)
			}
			t.Logf("%s -> %s", svc.name, link)
		})
	}
}
