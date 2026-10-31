package extras

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestParseYearEvents(t *testing.T) {
	wt := "==Events==\n===January===\n*[[January 1]] – The [[euro]] currency is established.<ref>{{Cite web |title=x}}</ref>\n*[[January 3]]\n**The [[Mars Polar Lander|MPL]] is launched by [[NASA]].<ref name=a/>\n**''[[The Sopranos]]'' premieres on HBO, beginning a new era.\n*short\n"
	got := parseYearEvents(wt)
	want := []string{
		"January 1 – The euro currency is established.",
		"January 3 – The MPL is launched by NASA.",
		"January 3 – The Sopranos premieres on HBO, beginning a new era.",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events: %q", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseMonthDay(t *testing.T) {
	cases := map[string][2]int{"03/14": {3, 14}, "3/14": {3, 14}, "Mar 14": {3, 14}, "14 March": {3, 14}, "12-25": {12, 25}}
	for in, want := range cases {
		m, d, ok := parseMonthDay(in)
		if !ok || m != want[0] || d != want[1] {
			t.Errorf("parseMonthDay(%q) = %d,%d,%v", in, m, d, ok)
		}
	}
	for _, bad := range []string{"13/01", "02/30", "abc"} {
		if _, _, ok := parseMonthDay(bad); ok {
			t.Errorf("parseMonthDay(%q) accepted", bad)
		}
	}
}

func TestNumberFacts(t *testing.T) {
	joined := strings.Join(numberFacts(28), "\n")
	for _, want := range []string{"28 is even.", "perfect number", "2^2 × 7", "XXVIII", "Binary: 11100"} {
		if !strings.Contains(joined, want) {
			t.Errorf("facts for 28 missing %q:\n%s", want, joined)
		}
	}
	joined = strings.Join(numberFacts(13), "\n")
	for _, want := range []string{"prime", "Fibonacci"} {
		if !strings.Contains(joined, want) {
			t.Errorf("facts for 13 missing %q", want)
		}
	}
	_ = numberFacts(-9223372036854775807)
	_ = numberFacts(0)
}

func TestNormalizeIPTarget(t *testing.T) {
	cases := map[string]string{
		"https://www.Example.com/path?q": "example.com",
		"1.1.1.1:443":                    "1.1.1.1",
		"[2606:4700::1111]:80":           "2606:4700::1111",
		"2606:4700::1111":                "2606:4700::1111",
		"google.com":                     "google.com",
	}
	for in, want := range cases {
		if got := normalizeIPTarget(in); got != want {
			t.Errorf("normalizeIPTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLookupEndpointsLive(t *testing.T) {
	if os.Getenv("JB_LIVE") == "" {
		t.Skip("set JB_LIVE=1 to hit real endpoints")
	}
	ctx := context.Background()
	if e, err := fetchWiktionary("serendipity"); err != nil || formatWiktionary("serendipity", e) == "" {
		t.Errorf("wiktionary: %v", err)
	}
	var out struct {
		Parse struct {
			Wikitext string `json:"wikitext"`
		} `json:"parse"`
	}
	if err := extGetJSON(ctx, "https://en.wikipedia.org/w/api.php?action=parse&prop=wikitext&section=1&format=json&formatversion=2&redirects=1&page=1969", &out, "User-Agent", wikiUA); err != nil {
		t.Fatal(err)
	}
	ev := parseYearEvents(out.Parse.Wikitext)
	if len(ev) < 20 {
		t.Errorf("only %d year events", len(ev))
	}
	for _, e := range ev[:5] {
		t.Log(e)
	}
	if wikiResolve(ctx, "alan turin") == "" {
		t.Error("opensearch resolve failed")
	}
}
