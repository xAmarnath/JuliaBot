package modules

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMentionUsernameUTF16(t *testing.T) {
	for _, tc := range []struct {
		text           string
		offset, length int32
		want           string
	}{
		{"@Alice hi", 0, 6, "alice"},
		{"hey 👋🏽 @Bob_1 there", 9, 6, "bob_1"},
		{"🇮🇳🇮🇳 @x", 9, 2, "x"},
		{"short", 3, 10, ""},
		{"", 0, 1, ""},
		{"@a", -1, 2, ""},
	} {
		if got := mentionUsername(tc.text, tc.offset, tc.length); got != tc.want {
			t.Errorf("mentionUsername(%q,%d,%d) = %q, want %q", tc.text, tc.offset, tc.length, got, tc.want)
		}
	}
}

func TestIsAFKCommand(t *testing.T) {
	for in, want := range map[string]bool{
		"/afk": true, "/afk reason here": true, "!afk": true, ".AFK": true, "/afk@JuliaBot sleeping": true,
		"brb": true, "brb food": true, "/afkusers": false, "afk": false, "hello /afk": false, "": false,
	} {
		if got := isAFKCommand(in); got != want {
			t.Errorf("isAFKCommand(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAFKDuration(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		ago  time.Duration
		want string
	}{
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m"},
		{2*time.Hour + 5*time.Minute, "2h 5m"},
		{50 * time.Hour, "2d 2h"},
	} {
		if got := afkDuration(now.Add(-tc.ago).Unix()); got != tc.want {
			t.Errorf("afkDuration(%s ago) = %q, want %q", tc.ago, got, tc.want)
		}
	}
}

func TestAFKStoreAndUsernameIndex(t *testing.T) {
	afkLoadOnce.Do(func() {})
	afkMu.Lock()
	afkList = map[int64]AFK{}
	afkByUsername = map[string]int64{}
	afkMu.Unlock()
	afkMu.Lock()
	afkList[42] = AFK{Name: "A", Username: "alice", Time: time.Now().Unix()}
	afkByUsername["alice"] = 42
	afkMu.Unlock()
	if afkCount() != 1 {
		t.Fatal("count")
	}
	if a, ok := afkGet(42); !ok || a.Name != "A" {
		t.Fatal("get")
	}
	afkMu.Lock()
	delete(afkList, 42)
	delete(afkByUsername, "alice")
	afkMu.Unlock()
	if afkCount() != 0 {
		t.Fatal("clear")
	}
}

func TestAFKNotifyRateLimit(t *testing.T) {
	for i := 0; i < afkPerUserPerMinute; i++ {
		if !afkShouldNotify(-10, 1) {
			t.Fatalf("reply %d blocked before the per-user limit", i+1)
		}
	}
	if afkShouldNotify(-10, 1) {
		t.Fatal("per-user limit not enforced")
	}
	for i := 0; i < afkPerChatPerMinute-afkPerUserPerMinute; i++ {
		if !afkShouldNotify(-10, int64(100+i)) {
			t.Fatalf("other user blocked early at %d", i)
		}
	}
	if afkShouldNotify(-10, 999) {
		t.Fatal("per-chat limit not enforced")
	}
	if !afkShouldNotify(-11, 1) {
		t.Fatal("limit leaked into another chat")
	}
}

func TestLastSeenBufferServesReads(t *testing.T) {
	lastSeenFlusher.Do(func() {})
	_ = saveLastSeen(&lastSeenEntry{UserID: 7, ChatID: -100, Name: "x", Time: 100})
	_ = saveLastSeen(&lastSeenEntry{UserID: 7, ChatID: -200, Name: "x", Time: 200})
	if e, _ := loadLastSeen(-100, 7); e == nil || e.Time != 100 {
		t.Fatalf("buffered entry not served: %+v", e)
	}
	if e, _ := loadAnyLastSeen(7); e == nil || e.ChatID != -200 {
		t.Fatalf("latest entry not served: %+v", e)
	}
}

func TestHelpPagesSplitWithinLimit(t *testing.T) {
	var b strings.Builder
	for i := range 400 {
		fmt.Fprintf(&b, "<code>/cmd%d</code> — does thing number %d\n", i, i)
	}
	pages := helpPages(b.String())
	if len(pages) < 2 {
		t.Fatalf("expected pagination, got %d page", len(pages))
	}
	joined := strings.Join(pages, "\n")
	if strings.Count(joined, "<code>") != 400 || strings.Count(joined, "</code>") != 400 {
		t.Fatal("lines lost or split mid-tag")
	}
	for i, p := range pages {
		if len(p) > helpPageLimit {
			t.Errorf("page %d is %d bytes", i, len(p))
		}
	}
	if got := helpPages("short"); len(got) != 1 || got[0] != "short" {
		t.Fatal("short help changed")
	}
}

func TestHelpDedupAndFuzzyFind(t *testing.T) {
	var m Modules
	m.AddModule("Rules", "old")
	m.AddModule("rules", "new")
	m.AddModule("Blacklist", "bl")
	m.AddModule("Blackjack", "bj")
	if len(m.Mod) != 3 || m.GetHelp("RULES") != "new" {
		t.Fatalf("duplicate registration not replaced: %+v", m.Mod)
	}
	if _, ok := m.find("rul"); !ok {
		t.Error("unique prefix not found")
	}
	if _, ok := m.find("black"); ok {
		t.Error("ambiguous match accepted")
	}
}

func TestHelpGroupsMergeSections(t *testing.T) {
	var m Modules
	for _, n := range []string{"Admin", "SilentMode", "Bans", "AFKStatus", "Anime", "Crypto", "Misc", "Rules", "TempRules", "Files", "Start", "Dev", "Snipe", "Tools"} {
		m.AddModule(n, "<b>"+n+"</b> help")
	}
	got := map[string]string{}
	for _, v := range m.sorted() {
		got[v.Name] = v.Help
	}
	for _, want := range []string{"Admin", "Bans", "AFK", "Misc", "Rules", "Dev", "Tools"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("missing section %s in %v", want, got)
		}
	}
	for _, gone := range []string{"SilentMode", "AFKStatus", "Anime", "Crypto", "TempRules", "Files", "Start", "Snipe"} {
		if _, ok := got[gone]; ok {
			t.Errorf("%s should be merged", gone)
		}
	}
	if !strings.HasPrefix(got["Misc"], "<b>Misc</b>") || !strings.Contains(got["Misc"], "Anime") || !strings.Contains(got["Misc"], "Crypto") {
		t.Errorf("misc merge wrong: %q", got["Misc"])
	}
	if !strings.HasPrefix(got["Admin"], "<b>Admin</b>") || !strings.Contains(got["Admin"], "SilentMode") {
		t.Errorf("admin merge wrong: %q", got["Admin"])
	}
	if mod, ok := m.find("anime"); !ok || mod.Name != "Misc" {
		t.Errorf("old name lookup: %v %v", mod.Name, ok)
	}
}
