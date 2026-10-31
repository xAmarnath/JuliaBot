package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestEvalPeerLiteral(t *testing.T) {
	tests := []struct {
		name string
		msg  *tg.NewMessage
		want string
	}{
		{"channel", &tg.NewMessage{Peer: &tg.InputPeerChannel{ChannelID: 1222527314, AccessHash: 987}}, "&tg.InputPeerChannel{ChannelID: 1222527314, AccessHash: 987}"},
		{"group", &tg.NewMessage{Peer: &tg.InputPeerChat{ChatID: 123}}, "&tg.InputPeerChat{ChatID: 123}"},
		{"private", &tg.NewMessage{Peer: &tg.InputPeerUser{UserID: 456, AccessHash: 789}}, "&tg.InputPeerUser{UserID: 456, AccessHash: 789}"},
		{"self", &tg.NewMessage{Peer: &tg.InputPeerSelf{}}, "&tg.InputPeerSelf{}"},
		{"channel fallback", &tg.NewMessage{Channel: &tg.Channel{ID: 123, AccessHash: 456}}, "&tg.InputPeerChannel{ChannelID: 123, AccessHash: 456}"},
		{"group fallback", &tg.NewMessage{Chat: &tg.ChatObj{ID: 123}}, "&tg.InputPeerChat{ChatID: 123}"},
		{"user fallback", &tg.NewMessage{Sender: &tg.UserObj{ID: 123, AccessHash: 456}}, "&tg.InputPeerUser{UserID: 123, AccessHash: 456}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evalPeerLiteral(tt.msg)
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	for _, msg := range []*tg.NewMessage{nil, {}, {Peer: (*tg.InputPeerChannel)(nil)}} {
		if _, err := evalPeerLiteral(msg); err == nil {
			t.Fatal("expected invalid peer error")
		}
	}
}

// Compile and exercise the actual generated program with the real dependency.
// No Telegram connection or credentials are used.
func TestGeneratedEvalBootstrap(t *testing.T) {
	dir, err := os.MkdirTemp(".", "eval-bootstrap-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	source := fmt.Sprintf(boiler_code_for_eval, "", 42, int64(1222527314), "&tg.InputPeerChannel{ChannelID: 1222527314, AccessHash: 987}", "_ = 0")
	if strings.Contains(source, "%!") {
		t.Fatal("invalid template formatting")
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main_test.go"), []byte(generatedEvalTests), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "test", "-race", "-count=1", "-v", ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated eval: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

const generatedEvalTests = `package main
import (
 "bufio"
 "io"
 "strings"
 "testing"
 tg "github.com/xAmarnath/gogram/telegram"
)
func TestFramedInput(t *testing.T) {
 for _, cache := range []string{"", "{}", strings.Repeat("x", 100000)} {
  reader := bufio.NewReader(strings.NewReader("synthetic-session\x00" + cache + "\x00"))
  session, err := readStdinValue(reader)
  if err != nil || session != "synthetic-session" { t.Fatalf("session: %q %v", session, err) }
  got, err := readStdinValue(reader)
  if err != nil || got != cache { t.Fatalf("cache bytes: got %d want %d, error %v", len(got), len(cache), err) }
 }
 for _, input := range []string{"", "unterminated"} {
  if _, err := readStdinValue(bufio.NewReader(strings.NewReader(input))); err != io.EOF { t.Fatalf("expected EOF, got %v", err) }
 }
}
func TestOriginalReaderReproduction(t *testing.T) {
 input := strings.NewReader("session\x00{\"cache\":true}\x00")
 first := bufio.NewReader(input)
 first.ReadString('\x00')
 // The original code discarded first (including its buffered cache bytes).
 lost, err := bufio.NewReader(input).ReadString('\x00')
 if err != io.EOF || lost != "" { t.Fatalf("original failure did not reproduce: %q %v", lost, err) }
}
func TestCacheAndPeer(t *testing.T) {
 cache := tg.NewCache("", &tg.CacheConfig{Memory: true, LogLevel: tg.LogDisable})
 if err := cache.ImportJSON([]byte("{")); err == nil { t.Fatal("invalid cache accepted") }
 original := tg.NewCache("", &tg.CacheConfig{Memory: true, LogLevel: tg.LogDisable})
 original.UpdatePeersToCache(nil, []tg.Chat{&tg.Channel{ID: 1222527314, AccessHash: 987, Title: "synthetic"}})
 data, err := original.ExportJSON()
 if err != nil { t.Fatal(err) }
 if err := cache.ImportJSON(data); err != nil { t.Fatal(err) }
 if err := cache.BindToUser(456); err != nil { t.Fatal(err) }
 c := &tg.Client{Cache: cache}
 peer, err := c.ResolvePeer("-1001222527314")
 if err != nil { t.Fatal(err) }
 ch, ok := peer.(*tg.InputPeerChannel)
 if !ok || ch.ChannelID != 1222527314 || ch.AccessHash != 987 { t.Fatalf("bad imported peer: %#v", peer) }
 emptyClient := &tg.Client{Cache: tg.NewCache("", &tg.CacheConfig{Memory: true, LogLevel: tg.LogDisable})}
 for _, input := range []tg.InputPeer{chatPeer, &tg.InputPeerChat{ChatID: 123}, &tg.InputPeerUser{UserID: 456, AccessHash: 789}} {
  got, err := emptyClient.ResolvePeer(input)
  if err != nil || got != input { t.Fatalf("typed peer changed with empty cache: %#v %v", got, err) }
 }
}
`
