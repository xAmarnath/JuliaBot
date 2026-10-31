package modules

import (
	"context"
	"testing"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestTransferAccountRequiresExplicitOptIn(t *testing.T) {
	bot, user := &relayFake{}, &relayFake{}
	s := newFileTransfers(bot, user, 10, 20)
	previous := transferService.Swap(s)
	t.Cleanup(func() { s.Close(); transferService.Store(previous) })
	for _, ctx := range []context.Context{nil, context.Background(), mediaContext(tg.MediaOptions{}), mediaContext(tg.MediaOptions{Upload: &tg.UploadOptions{Ctx: context.Background()}})} {
		if transferForContext(bot, ctx) != nil {
			t.Fatal("ordinary module media selected the transfer account")
		}
	}
	ctx, cancel := context.WithCancel(WithTransferAccount(nil))
	defer cancel()
	if transferForContext(bot, ctx) != s {
		t.Fatal("explicit file command did not select the transfer account")
	}
	if transferForContext(user, ctx) != nil {
		t.Fatal("another client selected the main bot's relay")
	}
	s.Close()
	if UserTransfersEnabled() || transferForContext(bot, ctx) != nil {
		t.Fatal("closed relay still selected")
	}
}

func TestCloseOldRelayKeepsReplacement(t *testing.T) {
	old := newFileTransfers(&relayFake{}, &relayFake{}, 10, 20)
	next := newFileTransfers(&relayFake{}, &relayFake{}, 10, 20)
	previous := transferService.Swap(next)
	t.Cleanup(func() { next.Close(); transferService.Store(previous) })
	old.Close()
	if transferService.Load() != next {
		t.Fatal("closing an old relay cleared the current one")
	}
}
