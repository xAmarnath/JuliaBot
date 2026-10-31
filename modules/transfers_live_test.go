package modules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	tg "github.com/xAmarnath/gogram/telegram"
	"github.com/joho/godotenv"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLiveBotMarkup(t *testing.T) {
	if os.Getenv("JB_BOT_MARKUP_TEST") != "1" {
		t.Skip("JB_BOT_MARKUP_TEST not set")
	}
	if err := godotenv.Load("../.env"); err != nil {
		t.Fatal(err)
	}
	app, _ := strconv.Atoi(os.Getenv("APP_ID"))
	bot, err := tg.NewClient(tg.ClientConfig{AppID: int32(app), AppHash: os.Getenv("APP_HASH"), MemorySession: true, DisableCache: true, SessionName: "markup-check", LogLevel: tg.LogError})
	if err != nil {
		t.Fatal(err)
	}
	defer bot.Terminate()
	if _, err = bot.Conn(); err != nil {
		t.Fatal(err)
	}
	if err = bot.LoginBot(os.Getenv("BOT_TOKEN")); err != nil {
		t.Fatal(err)
	}
	peer, err := bot.ResolvePeer("rfahnol8")
	if err != nil {
		t.Fatal(err)
	}
	m, err := bot.SendMessage(peer, "Transfer button check", &tg.SendOptions{ReplyMarkup: transferCancelKeyboard(1)})
	if err != nil {
		t.Fatal(err)
	}
	defer bot.DeleteMessages(peer, []int32{m.ID})
	if _, err = m.Edit("Transfer button check finished"); err != nil {
		t.Fatal(err)
	}
	got, err := bot.GetMessageByID(peer, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Message.ReplyMarkup != nil {
		t.Fatal("omitted reply markup did not remove the button")
	}
}

func TestLiveDualClient(t *testing.T) {
	if os.Getenv("JB_LIVE_TEST") != "1" {
		t.Skip("JB_LIVE_TEST not set")
	}
	if e := godotenv.Load("../.env"); e != nil {
		t.Fatal(e)
	}
	app, _ := strconv.Atoi(os.Getenv("APP_ID"))
	bot, e := tg.NewClient(tg.ClientConfig{AppID: int32(app), AppHash: os.Getenv("APP_HASH"), MemorySession: true, SessionName: "jb-live-bot", LogLevel: tg.LogError})
	if e != nil {
		t.Fatal(e)
	}
	defer bot.Terminate()
	if _, e = bot.Conn(); e != nil {
		t.Fatal(e)
	}
	if e = bot.LoginBot(os.Getenv("BOT_TOKEN")); e != nil {
		t.Fatal(e)
	}
	user, e := tg.NewClient(tg.ClientConfig{AppID: int32(app), AppHash: os.Getenv("APP_HASH"), StringSession: os.Getenv("USER_SESSION"), MemorySession: true, SessionName: "jb-live-user", DisableCache: true, LogLevel: tg.LogError})
	if e != nil {
		t.Fatal(e)
	}
	defer user.Terminate()
	if _, e = user.Conn(); e != nil {
		t.Fatal(e)
	}
	if _, e = user.GetMe(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(WithTransferAccount(context.Background()), 15*time.Minute)
	defer cancel()
	if e = InitTransfers(ctx, bot, user); e != nil {
		t.Fatal(e)
	}
	defer func() { CloseTransfers(); transferService.Store(nil) }()
	s := transferService.Load()
	t.Logf("Main @%s; helper premium=%v", bot.Me().Username, user.Me().Premium)
	limits, e := user.GetUploadLimits(ctx)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("Helper file cap: %d bytes", limits.MaxFileSize)
	if os.Getenv("JB_FULL_SPLIT_TEST") == "1" {
		testFullSplitCommand(t, ctx, bot, user, s, limits.MaxFileSize)
		return
	}
	payload := bytes.Repeat([]byte("juliabot dual-client audit\n"), 8192)
	status, e := bot.SendMessage(s.userPeer, "Julia bot transfer integration test")
	if e != nil {
		t.Fatal(e)
	}
	defer s.cleanup(bot, s.userPeer, status)
	result, e := TransferUploadEdit(status, payload, &tg.MediaOptions{FileName: "jb-transfer-test.bin", ForceDocument: true, Caption: "Transfer integration test", Upload: &tg.UploadOptions{Ctx: ctx}})
	if e != nil {
		t.Fatal(e)
	}
	if result == nil || transferMediaKey(result.Media()) == "" {
		t.Fatal("final bot message lacks file")
	}
	f, e := TransferDownload(result, &tg.DownloadOptions{Ctx: ctx, FileName: t.TempDir() + "/roundtrip.bin"})
	if e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(f)
	if e != nil {
		t.Fatal(e)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("roundtrip hash mismatch")
	}
	data, _, e := TransferDownloadChunk(ctx, result, 0, 4096, 4096)
	if e != nil {
		t.Fatal(e)
	}
	if len(data) < 4096 || !bytes.Equal(data[:4096], payload[:4096]) {
		t.Fatal("chunk mismatch")
	}
	t.Logf("Roundtrip verified: %d bytes, bot edit + helper download + chunk", len(got))
	for _, helper := range []bool{true, false} {
		t.Run(fmt.Sprintf("split_helper_%v", helper), func(t *testing.T) {
			if !helper {
				transferService.Store(nil)
				defer transferService.Store(s)
			}
			payload := make([]byte, 2*(512<<10)+7919)
			for i := range payload {
				payload[i] = byte((i*31 + i/8191) % 251)
			}
			path := t.TempDir() + "/split.bin"
			if err := os.WriteFile(path, payload, 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			partSize, count, err := uploadPartSize(int64(len(payload)), limits.MaxFileSize, 512<<10)
			if err != nil || count != 3 {
				t.Fatal("split count", count, err)
			}
			var joined []byte
			for i := int64(0); i < count; i++ {
				name := fmt.Sprintf("split.bin.part%05d", i+1)
				n := min(partSize, int64(len(payload))-i*partSize)
				source := tg.ReaderAtSource{Reader: io.NewSectionReader(file, i*partSize, n), Size: n, Name: name}
				status, err := bot.SendMessage(s.userPeer, "Split upload integration test")
				if err != nil {
					t.Fatal(err)
				}
				defer s.cleanup(bot, s.userPeer, status)
				var media any = source
				if i == 1 {
					media = &source
				}
				caption := uploadCompletedCaption(name, time.Second)
				result, err := TransferUploadEdit(status, media, &tg.MediaOptions{FileName: name, ForceDocument: true, Caption: caption, ParseMode: tg.HTML, Upload: &tg.UploadOptions{Ctx: ctx, ProgressManager: TransferProgress(status)}})
				if err != nil {
					t.Fatal(err)
				}
				if result.File == nil || result.File.Name != name || result.File.Size != n || result.MessageText() != name+"\nUploaded in 1.00 seconds." {
					t.Fatalf("part metadata mismatch: %+v caption=%q", result.File, result.MessageText())
				}
				downloaded, err := TransferDownload(result, &tg.DownloadOptions{Ctx: ctx, FileName: t.TempDir() + "/" + name})
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(downloaded)
				if err != nil || int64(len(data)) != n {
					t.Fatal("part length", len(data), err)
				}
				joined = append(joined, data...)
			}
			if sha256.Sum256(joined) != sha256.Sum256(payload) {
				t.Fatal("reconstructed split file hash mismatch")
			}
			t.Logf("Verified %d parts, %d bytes, filenames, captions and reconstructed SHA256", count, len(joined))
		})
	}
}

func testFullSplitCommand(t *testing.T, ctx context.Context, bot, user *tg.Client, s *FileTransfers, limit int64) {
	t.Helper()
	const size int64 = 10 << 30
	name := fmt.Sprintf("jb-full-split-%d.bin", time.Now().UnixNano())
	path := t.TempDir() + "/" + name
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	partSize, count, err := uploadPartSize(size, limit, 0)
	if err != nil || count != 3 {
		t.Fatal("part sizing", count, err)
	}
	for i := int64(0); i < count; i++ {
		stamp := bytes.Repeat([]byte{byte(i + 1)}, 4096)
		if _, err = file.WriteAt(stamp, i*partSize); err != nil {
			t.Fatal(err)
		}
	}
	request, err := bot.SendMessage(s.userPeer, "/ul "+path)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err = UploadHandle(request); err != nil {
		t.Fatal(err)
	}
	t.Logf("Full /ul handler returned after %.2f seconds", time.Since(started).Seconds())
	history, err := user.GetHistory(s.botPeer, &tg.HistoryOption{Limit: 30})
	if err != nil {
		t.Fatal(err)
	}
	parts := make(map[string]*tg.NewMessage)
	complete := false
	for i := range history {
		m := &history[i]
		if strings.Contains(m.MessageText(), name) || (m.File != nil && strings.HasPrefix(m.File.Name, name)) {
			defer s.cleanup(user, s.botPeer, m)
		}
		if strings.Contains(m.MessageText(), "Uploaded all 3 parts of "+path) {
			complete = true
		}
		if m.File != nil && strings.HasPrefix(m.File.Name, name+".part") {
			parts[m.File.Name] = m
		}
	}
	if len(parts) != 3 || !complete {
		t.Fatalf("handler stopped early: parts=%d completion=%v", len(parts), complete)
	}
	for i := int64(0); i < count; i++ {
		partName := fmt.Sprintf("%s.part%05d", name, i+1)
		m := parts[partName]
		n := min(partSize, size-i*partSize)
		if m == nil || m.File.Size != n || !strings.Contains(m.MessageText(), "Uploaded in ") {
			t.Fatalf("invalid part %s: %+v", partName, m)
		}
		data, _, err := user.DownloadChunkContext(ctx, m.Media(), 0, 4096, 4096)
		if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{byte(i + 1)}, 4096)) {
			t.Fatalf("part %d source offset mismatch: %v", i+1, err)
		}
		t.Logf("Verified %s: %d bytes and source offset %d", partName, n, i*partSize)
	}
	for _, stat := range user.GetTransferStats() {
		t.Logf("Transfer stats: %+v", stat)
	}
}
