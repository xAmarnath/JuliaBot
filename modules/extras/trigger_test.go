package extras

import (
	"strings"
	"testing"
)

func TestTriggerMatching(t *testing.T) {
	for _, tc := range []struct {
		trigger, text string
		want          bool
	}{
		{"spam", "this is spam", true},
		{"spam", "SPAM here", true},
		{"spam", "spammer", false},
		{"spam", "antispam", false},
		{"free money", "get FREE   money now", false},
		{"free money", "get free money now", true},
		{"regex:fr[e3]{2}\\s*m[o0]ney", "fr33 m0ney!!", true},
		{"regex:fr[e3]{2}\\s*m[o0]ney", "freemoney", true},
		{"regex:t\\.me/\\w+", "join t.me/scamgroup", true},
		{"regex:t\\.me/\\w+", "tme/x", false},
		{"/^hello$/", "HELLO", true},
		{"/^hello$/", "hello there", false},
		{"regex:தமிழ்", "இது தமிழ் உரை", true},
		{"中文", "这是中文测试", true},
	} {
		trig, err := compileTrigger(tc.trigger)
		if err != nil {
			t.Fatalf("compile %q: %v", tc.trigger, err)
		}
		if got := trig.match(tc.text, strings.ToLower(tc.text)); got != tc.want {
			t.Errorf("%q vs %q = %v, want %v", tc.trigger, tc.text, got, tc.want)
		}
	}
}

func TestTriggerRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"", "   ", "regex:", "regex:(", "regex:.*", "regex:.+", "/.*/", "x", "regex:" + strings.Repeat("a", 300)} {
		if _, err := compileTrigger(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTriggerKeyNormalization(t *testing.T) {
	for in, want := range map[string]string{
		"  Hello   World ": "hello world",
		"regex:ABC":        "regex:ABC",
		"/Pat/":            "regex:Pat",
		"REGEX: x+y":       "regex:x+y",
	} {
		if got := normalizeTriggerKey(in); got != want {
			t.Errorf("normalizeTriggerKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTriggerMatchInputIsBounded(t *testing.T) {
	trig, _ := compileTrigger("regex:needle")
	long := strings.Repeat("a", maxMatchInput+10) + "needle"
	if trig.match(long, long) {
		t.Error("matched beyond the input cap")
	}
	if got := truncateUTF8("aé", 2); got != "a" {
		t.Errorf("cut inside a rune: %q", got)
	}
}
