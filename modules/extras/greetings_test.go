package extras

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestGreetingEscapesAndDoesNotReprocessNames(t *testing.T) {
	user := &tg.UserObj{ID: 42, FirstName: "<b>{id}</b>", LastName: "A&B"}
	got := formatWelcomeText("{first}|{last}|{mention}|{id}|{chatname}", user, &tg.Channel{Title: "<group>"})
	want := `&lt;b&gt;{id}&lt;/b&gt;|A&amp;B|<a href="tg://user?id=42">&lt;b&gt;{id}&lt;/b&gt;</a>|42|&lt;group&gt;`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := formatWelcomeText("{username}", user, nil); !strings.Contains(got, "tg://user?id=42") {
		t.Fatal("missing username fallback")
	}
}

func TestGreetingDurationBounds(t *testing.T) {
	for input, want := range map[string]int{"off": 0, "0": 0, "5": 5, "30s": 30, "5m": 300, "24h": 86400} {
		if got, err := greetingDuration(input); err != nil || got != want {
			t.Errorf("%s: %d, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "4s", "25h", "-10", "999999999999999999999h", "9223372036854775807h", "0h", "abc"} {
		if _, err := greetingDuration(input); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestGreetingMembershipTransitions(t *testing.T) {
	for _, tc := range []struct {
		p       tg.ChannelParticipant
		present bool
	}{
		{nil, false}, {&tg.ChannelParticipantLeft{}, false}, {&tg.ChannelParticipantObj{}, true},
		{&tg.ChannelParticipantAdmin{}, true}, {&tg.ChannelParticipantBanned{Left: false}, true}, {&tg.ChannelParticipantBanned{Left: true}, false},
	} {
		if got := participantPresent(tc.p); got != tc.present {
			t.Errorf("%T: %v", tc.p, got)
		}
	}
	if kind, id := greetingMedia(nil); kind != "" || id != "" {
		t.Fatal("nil media")
	}
}

func TestCaptchaOnlyOneFinisherAndStaleStateRejected(t *testing.T) {
	st := &captchaState{ChatID: 123, UserID: 456, Cancel: make(chan struct{})}
	key := captchaStateKey(st.ChatID, st.UserID)
	captchaStates.Store(key, st)
	defer captchaStates.Delete(key)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if claimCaptcha(st) {
				winners.Add(1)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("finishers: %d", winners.Load())
	}
	select {
	case <-st.Cancel:
	default:
		t.Fatal("timeout not cancelled")
	}
	newState := &captchaState{ChatID: st.ChatID, UserID: st.UserID, Cancel: make(chan struct{})}
	captchaStates.Store(key, newState)
	if claimCaptcha(st) {
		t.Fatal("old state claimed new join")
	}
	if !claimCaptcha(newState) {
		t.Fatal("new join could not finish")
	}
}
