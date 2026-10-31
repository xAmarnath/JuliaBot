package modules

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	tg "github.com/xAmarnath/gogram/telegram"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAriaMagnetRoundtrip(t *testing.T) {
	binaryPath, err := exec.LookPath("aria2c")
	if err != nil {
		t.Skip("aria2c unavailable")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	peer := []byte{127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(peer[4:], uint16(port))
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("d8:intervali1e5:peers6:"))
		w.Write(peer)
		w.Write([]byte("e"))
	}))
	defer tracker.Close()
	payload := bytes.Repeat([]byte("juliabot-magnet-roundtrip"), 65536)
	const piece = 256 * 1024
	var hashes []byte
	for start := 0; start < len(payload); start += piece {
		sum := sha1.Sum(payload[start:min(start+piece, len(payload))])
		hashes = append(hashes, sum[:]...)
	}
	info := append([]byte(fmt.Sprintf("d6:lengthi%de4:name11:payload.bin12:piece lengthi%de6:pieces%d:", len(payload), piece, len(hashes))), hashes...)
	info = append(info, 'e')
	announce := tracker.URL + "/announce"
	metadata := append([]byte(fmt.Sprintf("d8:announce%d:%s4:info", len(announce), announce)), info...)
	metadata = append(metadata, 'e')
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "payload.bin"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	torrent := filepath.Join(dir, "payload.torrent")
	if err = os.WriteFile(torrent, metadata, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seedCtx, stop := context.WithCancel(context.Background())
	defer stop()
	cmd := exec.CommandContext(seedCtx, binaryPath, "--enable-dht=false", "--enable-dht6=false", "--disable-ipv6=true", "--check-integrity=true", "--seed-time=1", "--seed-ratio=0", "--summary-interval=0", fmt.Sprintf("--listen-port=%d", port), "--dir="+dir, torrent)
	output := &ariaOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stop(); cmd.Wait() }()
	for !strings.Contains(output.String(), "listening on TCP port") {
		select {
		case <-ctx.Done():
			t.Fatal("seeder startup", output.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	hash := sha1.Sum(info)
	uri := fmt.Sprintf("magnet:?xt=urn:btih:%x&tr=%s", hash, url.QueryEscape(announce))
	files, err := runAriaDownload(ctx, uri, t.TempDir(), func([]ariaItem) {})
	if err != nil {
		t.Fatal(err, output.String())
	}
	if len(files) != 1 {
		t.Fatal(files)
	}
	got, err := os.ReadFile(files[0])
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("magnet roundtrip mismatch", err)
	}
}

func TestTransferDCAndTiming(t *testing.T) {
	if TransferMediaDC(&tg.MessageMediaDocument{Document: &tg.DocumentObj{DcID: 5}}) != 5 {
		t.Fatal("document DC")
	}
	if TransferMediaDC(&tg.MessageMediaPhoto{Photo: &tg.PhotoObj{DcID: 2}}) != 2 {
		t.Fatal("photo DC")
	}
	var photo *tg.MessageMediaPhoto
	if TransferMediaDC(photo) != 0 {
		t.Fatal("nil media DC")
	}
	caption := uploadCompletedCaption("a<b.bin", 1250*time.Millisecond)
	if !strings.Contains(caption, "1.25 seconds") || !strings.Contains(caption, "a&lt;b.bin") {
		t.Fatal(caption)
	}
}

func TestAriaProgressStages(t *testing.T) {
	uri := "magnet:?xt=urn:btih:abc&dn=Example%20movie&xl=5900679188"
	text := ariaProgressText([]ariaItem{{Total: "5900679188", Connections: "4"}}, uri, time.Second)
	if !strings.Contains(text, "Example movie") || !strings.Contains(text, "Fetching torrent metadata") {
		t.Fatal(text)
	}
	item := ariaItem{Total: "5900679188", Connections: "3", Seeders: "1"}
	item.Bittorrent.Info.Name = "Received <title>"
	text = ariaProgressText([]ariaItem{item}, uri, time.Second)
	if !strings.Contains(text, "Received &lt;title&gt;") || !strings.Contains(text, "waiting for file data") || strings.Contains(text, "Fetching torrent metadata") {
		t.Fatal(text)
	}
}

func TestAriaMagnetLive(t *testing.T) {
	uri := os.Getenv("JB_MAGNET_TEST")
	if uri == "" {
		t.Skip("JB_MAGNET_TEST not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var current int64
	_, err := runAriaDownload(ctx, uri, t.TempDir(), func(items []ariaItem) {
		var total, speed int64
		total, current, speed, _, _ = ariaTotals(items)
		for _, item := range items {
			if len(item.FollowedBy) == 0 {
				t.Logf("total=%d bytes=%d speed=%d connections=%s seeders=%s metadata=%v", total, current, speed, item.Connections, item.Seeders, item.Bittorrent.Info.Name != "")
			}
		}
		if current >= 1<<20 {
			cancel()
		}
	})
	if current < 1<<20 {
		t.Fatalf("no payload progress: %d bytes, %v", current, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type relayFake struct {
	transferAPI
	upload  func(any, ...*tg.UploadOptions) (tg.InputFile, error)
	send    func(any, any, ...*tg.MediaOptions) (*tg.NewMessage, error)
	forward func(any, any, []int32, ...*tg.ForwardOptions) ([]tg.NewMessage, error)
	edit    func(any, int32, any, ...*tg.SendOptions) (*tg.NewMessage, error)
	deleted []int32
}

func (f *relayFake) UploadFile(m any, o ...*tg.UploadOptions) (tg.InputFile, error) {
	return f.upload(m, o...)
}

func TestSplitSourcePreparation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	progress := tg.NewProgressManager(5)
	options := &tg.UploadOptions{Ctx: ctx, ProgressManager: progress}
	payload := []byte("prefix-payload-suffix")
	source := tg.ReaderAtSource{Reader: io.NewSectionReader(bytes.NewReader(payload), 7, 7), Size: 7, Name: "file.part00002"}
	file := &tg.InputFileObj{ID: 123, Name: source.Name}
	calls := 0
	api := &relayFake{upload: func(m any, opts ...*tg.UploadOptions) (tg.InputFile, error) {
		calls++
		value := source
		switch v := m.(type) {
		case tg.ReaderAtSource:
			value = v
		case *tg.ReaderAtSource:
			value = *v
		default:
			t.Fatalf("unexpected source %T", m)
		}
		got, err := io.ReadAll(io.NewSectionReader(value.Reader, 0, value.Size))
		if err != nil || string(got) != "payload" {
			t.Fatalf("section bounds: %q %v", got, err)
		}
		if opts[0].Ctx != ctx || opts[0].ProgressManager != progress || opts[0].FileName != source.Name {
			t.Fatal("upload options lost")
		}
		return file, nil
	}}
	for _, media := range []any{source, &source} {
		if !transferNeedsUpload(media) {
			t.Fatal("source bypasses helper")
		}
		got, err := prepareTransferMedia(api, media, source.Name, options)
		if err != nil || got != file {
			t.Fatalf("prepared media: %T %v", got, err)
		}
	}
	if options.FileName != "" {
		t.Fatal("caller options mutated")
	}
	got, err := prepareTransferMedia(api, file, "", nil)
	if err != nil || got != file || calls != 2 {
		t.Fatal("existing file uploaded again")
	}
	var missing *tg.ReaderAtSource
	if _, err = prepareTransferMedia(api, missing, "", nil); err == nil {
		t.Fatal("nil source accepted")
	}
	cancel()
	if _, err = prepareTransferMedia(api, source, "", options); !errors.Is(err, context.Canceled) || calls != 2 {
		t.Fatal("cancelled upload started", err)
	}
}

func TestSplitRelayUploadFailure(t *testing.T) {
	want := errors.New("part upload failed")
	user := &relayFake{upload: func(any, ...*tg.UploadOptions) (tg.InputFile, error) { return nil, want }}
	user.send = func(any, any, ...*tg.MediaOptions) (*tg.NewMessage, error) {
		t.Fatal("sent media after upload failure")
		return nil, nil
	}
	s := newFileTransfers(&relayFake{}, user, 10, 20)
	defer s.Close()
	_, _, err := s.upload(context.Background(), tg.ReaderAtSource{}, tg.MediaOptions{})
	if !errors.Is(err, want) || len(s.pending) != 0 {
		t.Fatal("error or receipt cleanup lost", err)
	}
}

func TestTransferMessageFloodRetry(t *testing.T) {
	calls := 0
	started := time.Now()
	got, err := transferMessageCall(context.Background(), func() (int, error) {
		calls++
		if calls == 1 {
			return 0, errors.New("FLOOD_WAIT_1")
		}
		return 42, nil
	})
	if err != nil || got != 42 || calls != 2 || time.Since(started) < time.Second {
		t.Fatalf("retry: %d %d %v", got, calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, err = transferMessageCall(ctx, func() (int, error) {
		calls++
		cancel()
		return 0, errors.New("FLOOD_WAIT_300")
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("flood wait cancellation failed", err)
	}
	want := errors.New("CHAT_WRITE_FORBIDDEN")
	calls = 0
	_, err = transferMessageCall(context.Background(), func() (int, error) { calls++; return 0, want })
	if !errors.Is(err, want) || calls != 1 {
		t.Fatal("permanent error retried", err)
	}
}

func (f *relayFake) SendMedia(p, m any, o ...*tg.MediaOptions) (*tg.NewMessage, error) {
	return f.send(p, m, o...)
}
func (f *relayFake) EditMessage(p any, id int32, text any, o ...*tg.SendOptions) (*tg.NewMessage, error) {
	return f.edit(p, id, text, o...)
}
func (f *relayFake) Forward(p, s any, ids []int32, o ...*tg.ForwardOptions) ([]tg.NewMessage, error) {
	return f.forward(p, s, ids, o...)
}
func (f *relayFake) DeleteMessages(_ any, ids []int32, _ ...bool) (*tg.MessagesAffectedMessages, error) {
	f.deleted = append(f.deleted, ids...)
	return nil, nil
}
func relayMessage(sender int64, id int32, caption string, doc int64) *tg.NewMessage {
	return &tg.NewMessage{ID: id, Peer: &tg.InputPeerUser{UserID: sender}, Message: &tg.MessageObj{ID: id, PeerID: &tg.PeerUser{UserID: sender}, Message: caption, Media: &tg.MessageMediaDocument{Document: &tg.DocumentObj{ID: doc}}}}
}

func TestRelayAccountReferences(t *testing.T) {
	bot, user := &relayFake{}, &relayFake{}
	s := newFileTransfers(bot, user, 10, 20)
	defer s.Close()
	s.botPeer = &tg.InputPeerUser{UserID: 10}
	s.userPeer = &tg.InputPeerUser{UserID: 20}
	user.send = func(_ any, _ any, opts ...*tg.MediaOptions) (*tg.NewMessage, error) {
		token := opts[0].Caption.(string)
		s.receive(true, relayMessage(99, 1, token, 7))
		s.receive(true, relayMessage(20, 900, token, 8))
		return relayMessage(10, 700, token, 7), nil
	}
	got, cleanup, e := s.upload(context.Background(), []byte("data"), tg.MediaOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if got.ID != 900 || transferMediaKey(got.Media()) != "document:8" {
		t.Fatal("upload used wrong account reference")
	}
	cleanup()
	if len(user.deleted) != 1 || user.deleted[0] != 700 {
		t.Fatal("cleanup used receiver message ID")
	}
	bot.forward = func(_ any, _ any, ids []int32, _ ...*tg.ForwardOptions) ([]tg.NewMessage, error) {
		if ids[0] != 33 {
			t.Error("wrong source")
		}
		s.receive(false, relayMessage(10, 901, "", 8))
		return []tg.NewMessage{*relayMessage(20, 701, "", 8)}, nil
	}
	got, cleanup, e = s.forwardDownload(context.Background(), relayMessage(30, 33, "", 8))
	if e != nil {
		t.Fatal(e)
	}
	if got.ID != 901 {
		t.Fatal("download used sender's message")
	}
	cleanup()
	if len(bot.deleted) != 1 || bot.deleted[0] != 701 {
		t.Fatal("forward cleanup used receiver ID")
	}
}

func TestRelayCancellationAndTimeout(t *testing.T) {
	s := newFileTransfers(&relayFake{}, &relayFake{}, 10, 20)
	defer s.Close()
	key := transferReceipt{true, "pending"}
	ch, remove, e := s.subscribe(key)
	if e != nil {
		t.Fatal(e)
	}
	defer remove()
	if _, _, e = s.subscribe(key); e == nil {
		t.Fatal("duplicate subscription allowed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = s.receipt(ctx, ch); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	s.receiptTimeout = time.Millisecond
	if _, e = s.receipt(context.Background(), ch); e == nil {
		t.Fatal("missing receipt did not time out")
	}
	ctx, done := s.operation(context.Background())
	defer done()
	s.Close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("close did not cancel operation")
	}
	var doc *tg.MessageMediaDocument
	if transferMediaKey(doc) != "" {
		t.Fatal("nil media")
	}
}

func TestUploadSplitAndAuthorization(t *testing.T) {
	for _, tc := range []struct {
		s string
		n int64
	}{{"1900MiB", 1900 << 20}, {"3GiB", 3 << 30}, {"1.5MB", 1500000}, {"", 0}} {
		n, e := parseSplitSize(tc.s)
		if e != nil || n != tc.n {
			t.Fatalf("%s: %d %v", tc.s, n, e)
		}
	}
	for _, s := range []string{"-1", "0", "NaN", "1TB", "999999999999999999999GB"} {
		if _, e := parseSplitSize(s); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
	for _, tc := range []struct{ size, limit, requested, part, count int64 }{{2 << 30, 2 << 30, 0, 2 << 30, 1}, {(2 << 30) + 1, 2 << 30, 0, 2 << 30, 2}, {5 << 30, 4 << 30, 0, 4 << 30, 2}, {5 << 30, 4 << 30, 1 << 30, 1 << 30, 5}, {5 << 30, 2 << 30, 4 << 30, 2 << 30, 3}} {
		p, n, e := uploadPartSize(tc.size, tc.limit, tc.requested)
		if e != nil || p != tc.part || n != tc.count {
			t.Fatalf("%+v: %d %d %v", tc, p, n, e)
		}
	}
	if _, _, e := uploadPartSize(10001, 10, 1); e == nil {
		t.Fatal("too many parts accepted")
	}
	t.Setenv("UPLOAD_SPLIT_SIZE", "2GiB")
	name, sp, doc, size, e := uploadArguments(`"a file.mkv" -s --doc --split 1GiB`)
	if e != nil || name != "a file.mkv" || !sp || !doc || size != 1<<30 {
		t.Fatalf("arguments %q %v", name, e)
	}
	old := OwnerId
	OwnerId = 10
	defer func() { OwnerId = old }()
	t.Setenv("AUTH_USERS", "20, 30\n40")
	for _, id := range []int64{10, 20, 30, 40} {
		if !IsTransferUser(id) {
			t.Error("authorized rejected")
		}
	}
	for _, id := range []int64{0, -10, 99} {
		if IsTransferUser(id) {
			t.Error("unauthorized accepted")
		}
	}
}

func TestAriaMetadata(t *testing.T) {
	for _, s := range []string{"https://example.org/a", "http://example.org/a", "magnet:?xt=urn:btih:abc"} {
		if _, e := ariaSource(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"file:///etc/passwd", "--help", "magnet:?dn=foo"} {
		if _, e := ariaSource(s); e == nil {
			t.Fatal("invalid source accepted")
		}
	}
	total, current, speed, _, e := ariaTotals([]ariaItem{{Total: "100", Completed: "100", FollowedBy: []string{"real"}}, {Total: "1000", Completed: "500", Speed: "50", Status: "active"}})
	if e != nil || total != 1000 || current != 500 || speed != 50 {
		t.Fatal("metadata counted as downloaded content")
	}
}

func TestAriaHTTPAndCancel(t *testing.T) {
	if _, e := exec.LookPath("aria2c"); e != nil {
		t.Skip("aria2c unavailable")
	}
	payload := bytes.Repeat([]byte("juliabot"), 32768)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		http.ServeContent(w, r, "payload.bin", time.Now(), bytes.NewReader(payload))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	files, e := runAriaDownload(ctx, server.URL+"/payload.bin", dir, func([]ariaItem) {})
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 1 {
		t.Fatal(files)
	}
	got, e := os.ReadFile(files[0])
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatal("download hash mismatch", e)
	}
	if _, e = os.Stat(filepath.Join(dir, ".aria-rpc.conf")); !os.IsNotExist(e) {
		t.Fatal("RPC secret retained")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, e = runAriaDownload(ctx, server.URL+"/slow", t.TempDir(), func([]ariaItem) {})
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("cancellation failed", e)
	}
}
