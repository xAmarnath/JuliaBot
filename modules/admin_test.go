package modules

import (
	"testing"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestParseAdminDuration(t *testing.T) {
	ok := map[string]time.Duration{
		"":        0,
		"30s":     30 * time.Second,
		"1m":      time.Minute,
		"2h":      2 * time.Hour,
		"3d":      72 * time.Hour,
		"1w":      7 * 24 * time.Hour,
		"1h30m":   90 * time.Minute,
		"10":      10 * time.Minute,
		"2hours":  2 * time.Hour,
		"5 ":      5 * time.Minute,
		"1D":      24 * time.Hour,
		"2weeks":  14 * 24 * time.Hour,
		"45mins":  45 * time.Minute,
		"1d12h":   36 * time.Hour,
		"90min":   90 * time.Minute,
		"3days":   72 * time.Hour,
		"1hr":     time.Hour,
		"20secs":  20 * time.Second,
		"0m":      0,
		"366d":    366 * 24 * time.Hour,
		"52w":     52 * 7 * 24 * time.Hour,
		"1w2d3h4": 7*24*time.Hour + 2*24*time.Hour + 3*time.Hour + 4*time.Minute,
	}
	for in, want := range ok {
		got, err := ParseAdminDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseAdminDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"abc", "h", "1x", "-5m", "1.5h", "1 h", "m5", "99999999d", "1y", "spam"} {
		if _, err := ParseAdminDuration(in); err == nil {
			t.Errorf("ParseAdminDuration(%q) should fail", in)
		}
	}
}

func TestParseTempDuration(t *testing.T) {
	if _, err := ParseTempDuration(""); err == nil {
		t.Error("empty duration should fail")
	}
	if _, err := ParseTempDuration("30s"); err == nil {
		t.Error("30s is below the minimum")
	}
	if _, err := ParseTempDuration("367d"); err == nil {
		t.Error("367d is above the maximum")
	}
	if d, err := ParseTempDuration("1m"); err != nil || d != time.Minute {
		t.Errorf("1m: %v %v", d, err)
	}
	if d, err := ParseTempDuration("366d"); err != nil || d != MaxTempDuration {
		t.Errorf("366d: %v %v", d, err)
	}
}

func TestFormatAdminDuration(t *testing.T) {
	cases := map[time.Duration]string{
		time.Minute:                   "1 minute",
		90 * time.Minute:              "1 hour 30 minutes",
		7 * 24 * time.Hour:            "1 week",
		9 * 24 * time.Hour:            "1 week 2 days",
		2 * time.Hour:                 "2 hours",
		24*time.Hour + 45*time.Second: "1 day 45 seconds",
	}
	for in, want := range cases {
		if got := formatAdminDuration(in); got != want {
			t.Errorf("formatAdminDuration(%v) = %q; want %q", in, got, want)
		}
	}
}

func TestCommandArgs(t *testing.T) {
	cases := map[string]string{
		"/ban":                     "",
		"/ban @user":               "@user",
		"/ban@JuliaBot @user spam": "@user spam",
		"/ban\n@user reason":       "@user reason",
		"  /tban 2h  ":             "2h",
		"/note line1\nline2":       "line1\nline2",
	}
	for in, want := range cases {
		if got := CommandArgs(in); got != want {
			t.Errorf("CommandArgs(%q) = %q; want %q", in, got, want)
		}
	}
	first, rest := SplitFirstArg("@user  2h\nflooding chat")
	if first != "@user" || rest != "2h\nflooding chat" {
		t.Errorf("SplitFirstArg got %q %q", first, rest)
	}
	if f, r := SplitFirstArg(""); f != "" || r != "" {
		t.Errorf("SplitFirstArg empty got %q %q", f, r)
	}
}

func TestLooksLikeUserRef(t *testing.T) {
	cases := []struct {
		in       string
		replying bool
		want     bool
	}{
		{"@user", false, true},
		{"@", false, false},
		{"123456789", false, true},
		{"30", false, true},
		{"30", true, false},
		{"123456789", true, true},
		{"-1001234567890", true, true},
		{"2h", false, false},
		{"spam", true, false},
	}
	for _, c := range cases {
		if got := looksLikeUserRef(c.in, c.replying); got != c.want {
			t.Errorf("looksLikeUserRef(%q, %v) = %v; want %v", c.in, c.replying, got, c.want)
		}
	}
}

func TestUTF16Offsets(t *testing.T) {
	s := "a😀b"
	if got := utf16ToByteOffset(s, 0); got != 0 {
		t.Errorf("offset 0 -> %d", got)
	}
	if got := utf16ToByteOffset(s, 1); got != 1 {
		t.Errorf("offset 1 -> %d", got)
	}
	if got := utf16ToByteOffset(s, 3); got != 5 {
		t.Errorf("offset 3 -> %d", got)
	}
	if got := utf16ToByteOffset(s, 2); got != -1 {
		t.Errorf("offset inside surrogate pair should be -1, got %d", got)
	}
	if got := utf16ToByteOffset(s, 4); got != len(s) {
		t.Errorf("offset end -> %d", got)
	}
}

func TestLeadingMention(t *testing.T) {
	text := "/ban 😀Bob Smith being rude"
	// "/ban " = 5 units, mention "😀Bob Smith" = 2+9 = 11 units.
	ents := []tg.MessageEntity{&tg.MessageEntityMentionName{Offset: 5, Length: 11, UserID: 42}}
	uid, rest, ok := leadingMention(text, ents)
	if !ok || uid != 42 || rest != "being rude" {
		t.Fatalf("leadingMention = %d %q %v", uid, rest, ok)
	}
	later := []tg.MessageEntity{&tg.MessageEntityMentionName{Offset: 15, Length: 2, UserID: 7}}
	if _, _, ok := leadingMention("/ban reason by Bo", later); ok {
		t.Error("mention not at argument start must be ignored")
	}
	if _, _, ok := leadingMention("/ban", ents); ok {
		t.Error("no args means no mention")
	}
}

func TestIntersectRights(t *testing.T) {
	a := &tg.ChatAdminRights{BanUsers: true, DeleteMessages: true, AddAdmins: true}
	b := &tg.ChatAdminRights{BanUsers: true, PinMessages: true, AddAdmins: false}
	got := intersectRights(a, b)
	if !got.BanUsers || got.DeleteMessages || got.PinMessages || got.AddAdmins {
		t.Errorf("unexpected intersection %+v", got)
	}
	if r := intersectRights(a, nil); r.BanUsers {
		t.Error("nil rights must grant nothing")
	}
}

func TestAdminRightAllowed(t *testing.T) {
	if AdminRightAllowed(nil, "") {
		t.Error("nil admin has no rights")
	}
	creator := &AdminInfo{Creator: true}
	if !AdminRightAllowed(creator, "promote") {
		t.Error("creator has every right")
	}
	mod := &AdminInfo{Rights: &tg.ChatAdminRights{BanUsers: true}}
	if !AdminRightAllowed(mod, "ban") || AdminRightAllowed(mod, "delete") || !AdminRightAllowed(mod, "") {
		t.Error("rights mapping is wrong")
	}
	if AdminRightAllowed(&AdminInfo{}, "ban") {
		t.Error("admin with nil rights has no specific right")
	}
}

func TestChatIDForms(t *testing.T) {
	if NormChatID(123) != -1000000000123 || NormChatID(-5) != -5 {
		t.Error("NormChatID")
	}
	if rawChatID(-1000000000123) != 123 || rawChatID(-5) != 5 || rawChatID(7) != 7 {
		t.Error("rawChatID")
	}
	if !isChannelID(-1001234567890) || isChannelID(-12345) {
		t.Error("isChannelID")
	}
}

func TestStripTags(t *testing.T) {
	if got := stripTags("I need the <b>Ban Users</b> right &amp; more"); got != "I need the Ban Users right & more" {
		t.Errorf("stripTags = %q", got)
	}
}

func TestParseAdminErrorFriendly(t *testing.T) {
	if got := AdminFriendlyError(FriendlyError("custom"), "ban"); got != "custom" {
		t.Errorf("friendly passthrough = %q", got)
	}
	if got := AdminFriendlyError(errWrap("rpc error: USER_ADMIN_INVALID"), "ban"); got == "" || got == "custom" {
		t.Errorf("mapped error = %q", got)
	}
}

type errWrap string

func (e errWrap) Error() string { return string(e) }
