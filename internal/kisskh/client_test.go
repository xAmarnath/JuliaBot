package kisskh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleSRT = "1\n00:00:00,000 --> 00:00:01,000\nHello world\n\n"

func TestCountdownIsNotAReleasedVideo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "enc-kisskh") {
			fmt.Fprint(w, `{"status":200,"result":"key"}`)
			return
		}
		fmt.Fprint(w, `{"Video":"//www.tickcounter.com/widget/countdown/10855855","Type":2}`)
	}))
	defer server.Close()
	c := New()
	c.Base = server.URL
	c.Crypto = server.URL
	if _, err := c.Resolve(context.Background(), 227445); !errors.Is(err, ErrNotReleased) {
		t.Fatalf("countdown accepted: %v", err)
	}
	d := Drama{Episodes: []Episode{{ID: 227225, Sub: 5}, {ID: 227445}, {ID: 227446}}}
	if err := c.CheckReleases(context.Background(), &d); err != nil {
		t.Fatal(err)
	}
	if !d.Episodes[0].Released || d.Episodes[1].Released || d.Episodes[2].Released {
		t.Fatal("incorrect availability")
	}
}

func TestAPIWorkflow(t *testing.T) {
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != UserAgent {
			t.Error("missing user agent")
		}
		switch r.URL.Path {
		case "/api/DramaList/Search":
			if r.URL.Query().Get("q") != "lam & autumn" {
				t.Error("search not escaped")
			}
			fmt.Fprint(w, `[{"id":13907,"title":"The Lament of Autumn"}]`)
		case "/api/DramaList/Drama/13907":
			fmt.Fprint(w, `{"title":"The Lament of Autumn","episodes":[{"id":227122,"number":13},{"id":227121,"number":12}]}`)
		case "/enc-kisskh":
			if r.URL.Query().Get("text") != "227121" {
				t.Error("drama ID used instead of episode ID")
			}
			json.NewEncoder(w).Encode(map[string]any{"status": 200, "result": "a+b&="})
		case "/api/DramaList/Episode/227121.png":
			if r.URL.Query().Get("kkey") != "a+b&=" {
				t.Error("key not escaped")
			}
			fmt.Fprint(w, `{"Video":"https://cdn.example/video.m3u8"}`)
		case "/api/Sub/227121":
			fmt.Fprint(w, `[{"src":"https://subs.example/en.srt?v=a&b=2","label":"English","land":"en","default":true},{"src":"https://subs.example/ar.srt","label":"Arabic","land":"ar"}]`)
		case "/dec-kisskh":
			count++
			if count == 1 && r.URL.Query().Get("url") != "https://subs.example/en.srt?v=a&b=2" {
				t.Error("subtitle URL not escaped")
			}
			fmt.Fprint(w, sampleSRT)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{srv.URL, srv.URL, srv.Client()}
	ctx := context.Background()
	results, e := c.Search(ctx, "lam & autumn")
	if e != nil || len(results) != 1 {
		t.Fatal(results, e)
	}
	d, e := c.Drama(ctx, 13907)
	if e != nil || d.Episodes[0].ID != 227121 {
		t.Fatal(d, e)
	}
	s, e := c.Resolve(ctx, d.Episodes[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	if count != 2 || len(s.Subtitles) != 2 || s.Subtitles[1].Text != sampleSRT {
		t.Fatal("not all subtitles decrypted")
	}
}
func TestInputAndSubtitleValidation(t *testing.T) {
	for _, v := range []string{"13907", "https://kisskh.is/Drama/show?id=13907"} {
		id, ok := DramaID(v)
		if !ok || id != 13907 {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"lam", "-1", "https://other.test/?id=13907"} {
		if _, ok := DramaID(v); ok {
			t.Fatal(v)
		}
	}
	for _, v := range []string{`{"status":500}`, "<html>Error</html>", "U2FsdGVkX1encrypted", string([]byte{0xff})} {
		if ValidateSubtitle(v) == nil {
			t.Fatal("accepted invalid subtitles", v)
		}
	}
	if ValidateSubtitle(sampleSRT) != nil {
		t.Fatal("rejected SRT")
	}
}
func TestServiceErrors(t *testing.T) {
	for _, body := range []string{`{"status":500,"error":"unavailable"}`, `{"status":200,"result":""}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c := &Client{srv.URL, srv.URL, srv.Client()}
		if _, e := c.Resolve(context.Background(), 227121); e == nil || !strings.Contains(e.Error(), "key service") {
			t.Fatal(e)
		}
		srv.Close()
	}
}

func TestEmptyVideoRefreshesKey(t *testing.T) {
	keys, videos := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("_") == "" || r.Header.Get("Cache-Control") != "no-cache" {
			t.Error("request may reuse cached key/response")
		}
		if r.URL.Path == "/enc-kisskh" {
			keys++
			fmt.Fprintf(w, `{"status":200,"result":"key%d"}`, keys)
			return
		}
		videos++
		if r.URL.Query().Get("kkey") != fmt.Sprintf("key%d", videos) {
			t.Error("stale key reused")
		}
		if videos == 1 {
			fmt.Fprint(w, `{"Video":null,"Type":1}`)
		} else {
			fmt.Fprint(w, `{"Video":"","Video_tmp":" //cdn.example/ep12.m3u8 "}`)
		}
	}))
	defer srv.Close()
	c := &Client{srv.URL, srv.URL, srv.Client()}
	video, e := c.video(context.Background(), 227121)
	if e != nil || video != "https://cdn.example/ep12.m3u8" || keys != 2 || videos != 2 {
		t.Fatal(video, e, keys, videos)
	}
}
