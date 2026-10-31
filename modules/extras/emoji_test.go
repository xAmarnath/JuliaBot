package extras

import (
	"testing"
)

func TestSplitEmojiClusters(t *testing.T) {
	cases := map[string][]string{
		"hi 🎮 there": {"hi ", "🎮", " there"},
		"👨‍👩‍👧 fam":  {"👨‍👩‍👧", " fam"},
		"🇮🇳🇯🇵":       {"🇮🇳", "🇯🇵"},
		"👍🏽ok":       {"👍🏽", "ok"},
		"1️⃣ one":    {"1️⃣", " one"},
		"❤️ love":    {"❤️", " love"},
		"plain":      {"plain"},
		"":           nil,
		"🪙 9,999":    {"🪙", " 9,999"},
	}
	for in, want := range cases {
		segs := splitEmoji(in)
		var got []string
		for _, s := range segs {
			got = append(got, s.text)
		}
		if len(got) != len(want) {
			t.Errorf("%q -> %q, want %q", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%q -> %q, want %q", in, got, want)
			}
		}
	}
	if twemojiName("❤️", false) != "2764" || twemojiName("👨‍👩‍👧", false) != "1f468-200d-1f469-200d-1f467" {
		t.Error("twemoji names")
	}
}
