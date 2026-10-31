package extras

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAniListLive(t *testing.T) {
	if os.Getenv("SERVICES_LIVE") == "" {
		t.Skip("set SERVICES_LIVE=1 to call AniList")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, kind := range []string{"anime", "manga"} {
		e, err := fetchAniList(ctx, kind, "naruto")
		if err != nil || e == nil {
			t.Fatalf("%s: %v %v", kind, e, err)
		}
		c := buildAnimeCaption(e, kind)
		if !strings.Contains(c, "Naruto") || strings.Contains(c, "<br>") {
			t.Fatalf("%s caption: %s", kind, c)
		}
	}
	if e, err := fetchAniList(ctx, "anime", "zzqxjv no such title 12345"); err != nil || e != nil {
		t.Fatalf("missing title: %v %v", e, err)
	}
}

func TestGitHubContribLive(t *testing.T) {
	if os.Getenv("SERVICES_LIVE") == "" {
		t.Skip("set SERVICES_LIVE=1")
	}
	data, code, err := ghContribFetch("torvalds")
	if err != nil || code != 200 || data.TotalContributions <= 0 {
		t.Fatalf("%v %d %v", data, code, err)
	}
	days := ghContribFlatten(data.Contributions)
	if len(days) < 360 {
		t.Fatalf("only %d days", len(days))
	}
	if _, _, err := ghContribFetch("this-user-should-not-exist-zz9q-x"); err == nil {
		t.Fatal("missing user returned no error")
	}
}
