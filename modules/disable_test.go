package modules

import (
	"reflect"
	"testing"
)

func TestParseCommandNames(t *testing.T) {
	got := parseCommandNames("/Kang  .gif !paste kick@JuliaBot  -x ?y")
	want := []string{"kang", "gif", "paste", "kick", "x", "y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if len(parseCommandNames("   ")) != 0 {
		t.Fatal("empty input produced names")
	}
}

func TestDisabledLookupUsesCache(t *testing.T) {
	disabledMu.Lock()
	disabledCache[-500] = map[string]bool{"gif": true}
	disabledMu.Unlock()
	if !disabledCommands(-500)["gif"] || disabledCommands(-500)["kang"] {
		t.Fatal("cache not consulted")
	}
	if commandDisabledFor(nil, "gif") {
		t.Fatal("nil message treated as disabled")
	}
}

func TestUndisableableCommandsStayUnwrapped(t *testing.T) {
	for _, n := range []string{"disable", "enable", "disabled", "help", "start"} {
		if !undisableable[n] {
			t.Errorf("%s should never be disableable", n)
		}
	}
}
