package modules

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestLDLWidgetCadenceAndFloodBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writes := 0
		var editErr error
		v := &transferProgressView{widget: true, total: 1000, started: time.Now(), editInterval: time.Second,
			nextEdit: time.Now().Add(time.Second), writeState: func(context.Context, string) error {
				writes++
				return editErr
			}}
		update := func() { v.updateProgress(context.Background(), &tg.ProgressInfo{Current: 100}, 0, 1, 1, "File DC: 2") }
		time.Sleep(999 * time.Millisecond)
		update()
		if writes != 0 {
			t.Fatal("edited before one second")
		}
		time.Sleep(time.Millisecond)
		update()
		if writes != 1 {
			t.Fatal("did not edit at one second")
		}
		editErr = errors.New("FLOOD_WAIT_2")
		time.Sleep(time.Second)
		update()
		if writes != 2 {
			t.Fatal("did not edit at two seconds")
		}
		editErr = nil
		time.Sleep(2 * time.Second)
		update()
		if writes != 2 {
			t.Fatal("ignored flood wait padding")
		}
		time.Sleep(250 * time.Millisecond)
		update()
		if writes != 3 {
			t.Fatal("did not resume after flood wait")
		}
		time.Sleep(time.Second)
		update()
		if writes != 4 {
			t.Fatal("did not return to one-second cadence")
		}
	})
}

func TestLDLWidgetTickerJitterDoesNotSkipUpdates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writes := 0
		v := &transferProgressView{widget: true, total: 1000, started: time.Now(), editInterval: time.Second,
			writeState: func(context.Context, string) error { writes++; return nil }}
		for _, delay := range []time.Duration{1010 * time.Millisecond, 990 * time.Millisecond, 1010 * time.Millisecond, 990 * time.Millisecond} {
			time.Sleep(delay)
			v.updateProgress(context.Background(), &tg.ProgressInfo{Current: 100}, 0, 1, 1, "File DC: 2")
		}
		if writes != 4 {
			t.Fatalf("ticker jitter skipped updates: got %d, want 4", writes)
		}
	})
}

func TestTransferWidgetPayloadLimits(t *testing.T) {
	for name, source := range map[string]string{"transfer": transferWidgetHTML, "inline": inlineWidgetHTML} {
		var compressed bytes.Buffer
		z, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = z.Write([]byte(source))
		_ = z.Close()
		if len(source) > 32768 || compressed.Len() > 4096 || strings.ContainsRune(source, 0) {
			t.Fatal(name, "widget exceeds Telegram limits", len(source), compressed.Len())
		}
		t.Logf("%s HTML %d bytes; compressed %d bytes", name, len(source), compressed.Len())
	}
	for _, name := range []string{strings.Repeat("文件🙂", 500), strings.Repeat("\x00\n\"<>&", 500), strings.Repeat("\xff", 500)} {
		s := transferWidgetState{Phase: name, Name: name, Detail: name, Size: name, Speed: name, ETA: name, Elapsed: name, DC: name, Percent: 100, Part: math.MaxInt64, Parts: math.MaxInt64, Done: true}
		data := s.JSON()
		if len(data) > 1024 || !utf8.ValidString(data) || !json.Valid([]byte(data)) || strings.ContainsRune(data, 0) {
			t.Fatal("invalid state", len(data))
		}
	}
}

func TestTransferWidgetProgressAndTerminalState(t *testing.T) {
	var states []transferWidgetState
	v := &transferProgressView{widget: true, total: 1000, started: time.Now(), writeState: func(_ context.Context, data string) error {
		var s transferWidgetState
		if err := json.Unmarshal([]byte(data), &s); err != nil {
			t.Fatal(err)
		}
		states = append(states, s)
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	info := &tg.ProgressInfo{Current: 100, TotalSize: 500, CurrentSpeed: 20, ETA: 20}
	v.updateProgress(ctx, info, 500, 2, 2, "Upload DC: 4")
	if len(states) != 1 || states[0].Percent != 60 || states[0].Part != 2 || states[0].DC != "Upload DC: 4" {
		t.Fatal(states)
	}
	v.updateProgress(ctx, info, 0, 1, 2, "Upload DC: 4")
	if v.state.Part != 2 {
		t.Fatal("late part regressed progress")
	}
	v.updateProgress(ctx, info, 500, 2, 2, "Upload DC: 4")
	if len(states) != 1 {
		t.Fatal("progress not throttled")
	}
	if err := v.finishState("Completed", "Delivered"); err != nil {
		t.Fatal(err)
	}
	v.nextEdit = time.Time{}
	v.updateProgress(ctx, info, 500, 2, 2, "Upload DC: 4")
	if len(states) != 2 || !states[1].Done || states[1].Percent != 100 || states[1].Phase != "Completed" {
		t.Fatal("terminal state overwritten", states)
	}
}

func TestTransferWidgetCancellationStopsProgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writes := 0
	v := &transferProgressView{widget: true, total: 100, started: time.Now(), writeState: func(context.Context, string) error { writes++; return nil }}
	v.updateProgress(ctx, &tg.ProgressInfo{Current: 10}, 0, 1, 1, "File DC: 2")
	if writes != 0 {
		t.Fatal("progress after cancellation")
	}
	if err := v.finishState("Cancelled", "Partial download removed."); err != nil {
		t.Fatal(err)
	}
	if writes != 1 || !v.state.Done || v.state.Phase != "Cancelled" || v.state.Percent == 100 {
		t.Fatal(v.state)
	}
}

func TestTransferWidgetQueryAuthorization(t *testing.T) {
	savedOwner := OwnerId
	OwnerId = 77
	defer func() { OwnerId = savedOwner }()
	for _, peer := range []tg.Peer{&tg.PeerUser{UserID: 901}, &tg.PeerChat{ChatID: 901}, &tg.PeerChannel{ChannelID: 901}} {
		ctx, cancel := context.WithCancel(context.Background())
		key := fileTransferKey{901, 123}
		cancelMutex.Lock()
		downloadCancels[key] = activeFileTransfer{ctx, cancel, 88}
		cancelMutex.Unlock()
		q := &tg.UpdateBotWidgetQuery{QueryType: &tg.WidgetQueryTypeData{}, Peer: peer, MsgID: 123, UserID: 99, Data: []byte("filecancel")}
		if ok, _ := cancelWidgetTransfer(q); ok || ctx.Err() != nil {
			t.Fatal("another user cancelled")
		}
		q.UserID = 88
		q.MsgID = 124
		if ok, _ := cancelWidgetTransfer(q); ok {
			t.Fatal("wrong message accepted")
		}
		q.MsgID = 123
		q.Data = []byte("filecancel:123")
		if ok, _ := cancelWidgetTransfer(q); ok {
			t.Fatal("client-supplied transfer accepted")
		}
		q.Data = []byte("filecancel")
		if ok, _ := cancelWidgetTransfer(q); !ok || ctx.Err() == nil {
			t.Fatal("initiator could not cancel")
		}
		q.UserID = 77
		if ok, _ := cancelWidgetTransfer(q); !ok {
			t.Fatal("bot owner could not cancel")
		}
		cancelMutex.Lock()
		delete(downloadCancels, key)
		cancelMutex.Unlock()
		cancel()
		if ok, _ := cancelWidgetTransfer(q); ok {
			t.Fatal("stale transfer accepted")
		}
	}
}

func TestTransferWidgetUploadDelivery(t *testing.T) {
	for _, sendErr := range []error{nil, errors.New("CHAT_WRITE_FORBIDDEN")} {
		status := relayMessage(30, 100, "Uploading", 0)
		status.Message.Media = &tg.MessageMediaWidget{}
		status.Message.ReplyTo = &tg.MessageReplyHeaderObj{ReplyToMsgID: 99, ReplyToTopID: 42}
		bot := &relayFake{edit: func(any, int32, any, ...*tg.SendOptions) (*tg.NewMessage, error) {
			t.Fatal("attempted to replace widget")
			return nil, nil
		}}
		media := &tg.MessageMediaDocument{}
		bot.send = func(peer, got any, opts ...*tg.MediaOptions) (*tg.NewMessage, error) {
			if peer != status.Peer || got != media || opts[0].ReplyID != 99 || opts[0].TopicID != 42 || !opts[0].ForceDocument {
				t.Fatal("lost delivery options")
			}
			return relayMessage(30, 101, "Uploaded", 1), sendErr
		}
		_, err := deliverTransferUpload(context.Background(), bot, status, media, tg.MediaOptions{ForceDocument: true}, &tg.SendOptions{}, "")
		if !errors.Is(err, sendErr) || len(bot.deleted) != 0 {
			t.Fatal("widget must survive delivery", err, bot.deleted)
		}
	}
}

func TestWidgetFallbackRequiresExplicitRejection(t *testing.T) {
	if !widgetUnavailable(errors.New("INPUT_MEDIA_WIDGET_NOT_ALLOWED")) {
		t.Fatal("missing group fallback")
	}
	for _, err := range []error{context.DeadlineExceeded, errors.New("INPUT_MEDIA_WIDGET_TOO_LARGE"), errors.New("network timeout"), errors.New("CHAT_WRITE_FORBIDDEN")} {
		if widgetUnavailable(err) {
			t.Fatal("unsafe or hidden fallback", err)
		}
	}
}
