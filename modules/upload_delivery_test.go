package modules

import (
	"context"
	"errors"
	"testing"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestStickerRelayDeliveryUsesBotReference(t *testing.T) {
	bot, user := &relayFake{}, &relayFake{}
	s := newFileTransfers(bot, user, 10, 20)
	defer s.Close()
	s.botPeer = &tg.InputPeerUser{UserID: 10}
	user.send = func(_ any, _ any, options ...*tg.MediaOptions) (*tg.NewMessage, error) {
		token := options[0].Caption.(string)
		s.receive(true, relayMessage(20, 900, token, 88))
		return relayMessage(10, 700, token, 77), nil
	}
	received, cleanup, err := s.upload(context.Background(), []byte("webp"), tg.MediaOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	status := relayMessage(30, 100, "Uploading", 0)
	status.Message.ReplyTo = &tg.MessageReplyHeaderObj{ReplyToMsgID: 99, ReplyToTopID: 42}
	want := relayMessage(30, 101, "", 88)
	bot.edit = func(peer any, id int32, _ any, options ...*tg.SendOptions) (*tg.NewMessage, error) {
		if peer != status.Peer || id != 100 || options[0].Media != received.Media() {
			t.Fatal("wrong edit reference")
		}
		return nil, errors.New("[MEDIA_NEW_INVALID] (method: MessagesEditMessage) (code 400)")
	}
	bot.send = func(peer any, media any, options ...*tg.MediaOptions) (*tg.NewMessage, error) {
		if peer != status.Peer || media != received.Media() || transferMediaKey(media.(tg.MessageMedia)) != "document:88" {
			t.Fatal("delivery used user-account reference")
		}
		opt := options[0]
		if opt.ReplyID != 99 || opt.TopicID != 42 || !opt.Silent || !opt.Spoiler || opt.Caption != "sticker.webp" {
			t.Fatal("delivery options lost", opt)
		}
		if len(bot.deleted) != 0 || len(user.deleted) != 0 {
			t.Fatal("cleanup happened before delivery")
		}
		return want, nil
	}
	opt := tg.MediaOptions{Caption: "sticker.webp", Silent: true, Spoiler: true}
	send := transferSendOptions(opt)
	send.Media = received.Media()
	got, err := deliverTransferUpload(context.Background(), bot, status, received.Media(), opt, send, opt.Caption)
	if err != nil || got != want {
		t.Fatal(got, err)
	}
	if len(bot.deleted) != 1 || bot.deleted[0] != 100 {
		t.Fatal("progress not cleaned up", bot.deleted)
	}
}

func TestUploadDeliveryFailureAndEditSuccess(t *testing.T) {
	for _, tc := range []struct {
		name             string
		editErr, sendErr error
		fallback         bool
	}{
		{"editable media", nil, nil, false},
		{"unrelated error", errors.New("CHAT_WRITE_FORBIDDEN"), nil, false},
		{"fallback rejected", errors.New("MEDIA_NEW_INVALID"), errors.New("MEDIA_INVALID"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := relayMessage(30, 100, "Uploading", 0)
			bot := &relayFake{}
			bot.edit = func(any, int32, any, ...*tg.SendOptions) (*tg.NewMessage, error) { return status, tc.editErr }
			called := false
			bot.send = func(any, any, ...*tg.MediaOptions) (*tg.NewMessage, error) { called = true; return nil, tc.sendErr }
			got, err := deliverTransferUpload(context.Background(), bot, status, status.Media(), tg.MediaOptions{}, &tg.SendOptions{}, "caption")
			wantErr := tc.editErr
			if tc.fallback {
				wantErr = tc.sendErr
			}
			if !errors.Is(err, wantErr) || called != tc.fallback || len(bot.deleted) != 0 {
				t.Fatal("unexpected fallback or cleanup", err, called, bot.deleted)
			}
			if err == nil && got != status {
				t.Fatal("edited message lost")
			}
		})
	}
}

func TestUploadDeliveryCancellationDoesNotSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bot := &relayFake{edit: func(any, int32, any, ...*tg.SendOptions) (*tg.NewMessage, error) {
		cancel()
		return nil, errors.New("MEDIA_NEW_INVALID")
	}}
	bot.send = func(any, any, ...*tg.MediaOptions) (*tg.NewMessage, error) {
		t.Fatal("sent after cancellation")
		return nil, nil
	}
	_, err := deliverTransferUpload(ctx, bot, relayMessage(30, 100, "", 0), nil, tg.MediaOptions{}, &tg.SendOptions{}, "")
	if !errors.Is(err, context.Canceled) || len(bot.deleted) != 0 {
		t.Fatal(err, bot.deleted)
	}
}
