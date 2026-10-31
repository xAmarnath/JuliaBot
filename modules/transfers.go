package modules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

type transferAPI interface {
	UploadFile(any, ...*tg.UploadOptions) (tg.InputFile, error)
	SendMessage(any, any, ...*tg.SendOptions) (*tg.NewMessage, error)
	SendMedia(any, any, ...*tg.MediaOptions) (*tg.NewMessage, error)
	EditMessage(any, int32, any, ...*tg.SendOptions) (*tg.NewMessage, error)
	Forward(any, any, []int32, ...*tg.ForwardOptions) ([]tg.NewMessage, error)
	DeleteMessages(any, []int32, ...bool) (*tg.MessagesAffectedMessages, error)
	DownloadMedia(any, ...*tg.DownloadOptions) (string, error)
	DownloadChunkContext(context.Context, any, int, int, int, ...*tg.DownloadOptions) ([]byte, string, error)
}

type transferReceipt struct {
	toBot bool
	key   string
}

type FileTransfers struct {
	bot, user         transferAPI
	botID, userID     int64
	botPeer, userPeer tg.InputPeer
	ctx               context.Context
	cancel            context.CancelFunc
	mu                sync.Mutex
	pending           map[transferReceipt]chan *tg.NewMessage
	peerReady         chan struct{}
	peerOnce          sync.Once
	forwardGate       chan struct{}
	closeOnce         sync.Once
	handles           []func()
	receiptTimeout    time.Duration
}

var transferService atomic.Pointer[FileTransfers]

type transferAccountKey struct{}

// WithTransferAccount opts an explicit ldl, ul, or mirror operation into the
// secondary account. Ordinary module media always uses the bot by default.
func WithTransferAccount(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, transferAccountKey{}, true)
}

func transferForContext(bot transferAPI, ctx context.Context) *FileTransfers {
	if ctx == nil || ctx.Value(transferAccountKey{}) != true {
		return nil
	}
	s := transferService.Load()
	if s == nil || s.bot != bot || s.ctx.Err() != nil {
		return nil
	}
	return s
}

func mediaContext(opt tg.MediaOptions) context.Context {
	if opt.Upload != nil {
		return opt.Upload.Ctx
	}
	return nil
}

func transferMessageCall[T any](ctx context.Context, call func() (T, error)) (T, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var zero T
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		value, err := call()
		seconds := tg.GetFloodWait(err)
		if err == nil || seconds <= 0 || seconds > 600 || attempt >= 5 {
			return value, err
		}
		timer := time.NewTimer(time.Duration(seconds)*time.Second + 250*time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
}

func newFileTransfers(bot, user transferAPI, botID, userID int64) *FileTransfers {
	ctx, cancel := context.WithCancel(context.Background())
	return &FileTransfers{bot: bot, user: user, botID: botID, userID: userID, ctx: ctx, cancel: cancel,
		pending: make(map[transferReceipt]chan *tg.NewMessage), peerReady: make(chan struct{}),
		forwardGate: make(chan struct{}, 1), receiptTimeout: 30 * time.Second}
}

func InitTransfers(ctx context.Context, bot, user *tg.Client) error {
	if user == nil {
		return nil
	}
	if bot.Me() == nil || !bot.Me().Bot || user.Me() == nil || user.Me().Bot {
		return errors.New("transfers require a main bot and a secondary user account")
	}
	s := newFileTransfers(bot, user, bot.Me().ID, user.Me().ID)
	ready := false
	defer func() {
		if !ready {
			s.Close()
		}
	}()
	peer, err := user.ResolvePeer(bot.Me().Username)
	if err != nil {
		return fmt.Errorf("resolve main bot: %w", err)
	}
	s.botPeer = peer
	bh := bot.AddMessageHandler(tg.OnMessage, func(m *tg.NewMessage) error { s.receive(true, m); return nil }, tg.IsIncoming)
	bh.SetGroup(-90)
	uh := user.AddMessageHandler(tg.OnMessage, func(m *tg.NewMessage) error { s.receive(false, m); return nil }, tg.IsIncoming)
	uh.SetGroup(-90)
	s.handles = []func(){func() { _ = bot.RemoveHandle(bh) }, func() { _ = user.RemoveHandle(uh) }}
	if _, err := user.SendMessage(peer, "/start"); err != nil {
		return fmt.Errorf("start main bot from user account: %w", err)
	}
	setup, cancel := context.WithTimeout(ctx, s.receiptTimeout)
	defer cancel()
	select {
	case <-s.peerReady:
	case <-setup.Done():
		return fmt.Errorf("waiting for user-to-bot private chat: %w", setup.Err())
	}
	transferService.Store(s)
	ready = true
	return nil
}

func CloseTransfers() {
	if s := transferService.Load(); s != nil {
		s.Close()
	}
}

func (s *FileTransfers) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		transferService.CompareAndSwap(s, nil)
		for _, remove := range s.handles {
			remove()
		}
	})
}

func transferMediaKey(media tg.MessageMedia) string {
	switch m := media.(type) {
	case *tg.MessageMediaDocument:
		if m == nil {
			return ""
		}
		if d, ok := m.Document.(*tg.DocumentObj); ok && d != nil {
			return fmt.Sprintf("document:%d", d.ID)
		}
	case *tg.MessageMediaPhoto:
		if m == nil {
			return ""
		}
		if p, ok := m.Photo.(*tg.PhotoObj); ok && p != nil {
			return fmt.Sprintf("photo:%d", p.ID)
		}
	}
	return ""
}

func (s *FileTransfers) receive(toBot bool, m *tg.NewMessage) {
	if m == nil || m.Message == nil || m.IsOutgoing() {
		return
	}
	expected := s.botID
	if toBot {
		expected = s.userID
	}
	if m.SenderID() != expected || m.ChatID() != expected {
		return
	}
	if toBot && m.Peer != nil {
		s.peerOnce.Do(func() { s.userPeer = m.Peer; close(s.peerReady) })
	}
	if transferMediaKey(m.Media()) == "" {
		return
	}
	keys := []string{m.MessageText(), transferMediaKey(m.Media())}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		if ch := s.pending[transferReceipt{toBot, key}]; ch != nil {
			select {
			case ch <- m:
			default:
			}
			return
		}
	}
}

func (s *FileTransfers) operation(ctx context.Context) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	if s.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func (s *FileTransfers) subscribe(key transferReceipt) (<-chan *tg.NewMessage, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[key] != nil {
		return nil, nil, errors.New("file relay already pending")
	}
	ch := make(chan *tg.NewMessage, 1)
	s.pending[key] = ch
	return ch, func() { s.mu.Lock(); delete(s.pending, key); s.mu.Unlock() }, nil
}

func (s *FileTransfers) receipt(ctx context.Context, ch <-chan *tg.NewMessage) (*tg.NewMessage, error) {
	timer := time.NewTimer(s.receiptTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case m := <-ch:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return m, nil
	case <-timer.C:
		return nil, errors.New("timed out waiting for file in the private relay chat")
	}
}

func transferToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "jb-transfer:" + hex.EncodeToString(b[:])
}

func transferDownloadOptions(opts []*tg.DownloadOptions) tg.DownloadOptions {
	if len(opts) > 0 && opts[0] != nil {
		return *opts[0]
	}
	return tg.DownloadOptions{}
}

func transferMediaOptions(opts []*tg.MediaOptions) tg.MediaOptions {
	if len(opts) > 0 && opts[0] != nil {
		return *opts[0]
	}
	return tg.MediaOptions{}
}

func (s *FileTransfers) cleanup(api transferAPI, peer tg.InputPeer, m *tg.NewMessage) {
	if m != nil && m.ID != 0 {
		if _, err := api.DeleteMessages(peer, []int32{m.ID}); err != nil {
			if Client != nil {
				Client.Log.Warn("could not remove temporary relay message %d: %v", m.ID, err)
			}
		}
	}
}

func (s *FileTransfers) forwardDownload(ctx context.Context, original *tg.NewMessage) (*tg.NewMessage, func(), error) {
	if original == nil || original.Message == nil || transferMediaKey(original.Media()) == "" {
		return nil, nil, errors.New("message does not contain a downloadable file")
	}
	select {
	case s.forwardGate <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	defer func() { <-s.forwardGate }()
	ch, remove, err := s.subscribe(transferReceipt{false, transferMediaKey(original.Media())})
	if err != nil {
		return nil, nil, err
	}
	defer remove()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	forwarded, err := s.bot.Forward(s.userPeer, original.Peer, []int32{original.ID}, &tg.ForwardOptions{Silent: true})
	if err != nil {
		return nil, nil, fmt.Errorf("forward file to transfer account: %w", err)
	}
	cleanup := func() {
		for i := range forwarded {
			s.cleanup(s.bot, s.userPeer, &forwarded[i])
		}
	}
	received, err := s.receipt(ctx, ch)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return received, cleanup, nil
}

func (s *FileTransfers) copyDownload(ctx context.Context, media any) (*tg.NewMessage, func(), error) {
	token := transferToken()
	ch, remove, err := s.subscribe(transferReceipt{false, token})
	if err != nil {
		return nil, nil, err
	}
	defer remove()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	sent, err := s.bot.SendMedia(s.userPeer, media, &tg.MediaOptions{Caption: token, Silent: true})
	if err != nil {
		return nil, nil, fmt.Errorf("copy file to transfer account: %w", err)
	}
	cleanup := func() { s.cleanup(s.bot, s.userPeer, sent) }
	received, err := s.receipt(ctx, ch)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return received, cleanup, nil
}

func TransferDownload(m *tg.NewMessage, opts ...*tg.DownloadOptions) (string, error) {
	if m == nil || m.Client == nil {
		return "", errors.New("missing source message")
	}
	opt := transferDownloadOptions(opts)
	s := transferForContext(m.Client, opt.Ctx)
	if s == nil {
		return m.Download(opts...)
	}
	ctx, done := s.operation(opt.Ctx)
	defer done()
	opt.Ctx = ctx
	received, cleanup, err := s.forwardDownload(ctx, m)
	if err != nil {
		return "", err
	}
	defer cleanup()
	return s.user.DownloadMedia(received.Media(), &opt)
}

func TransferDownloadMedia(c *tg.Client, media any, opts ...*tg.DownloadOptions) (string, error) {
	opt := transferDownloadOptions(opts)
	s := transferForContext(c, opt.Ctx)
	if s == nil {
		return c.DownloadMedia(media, opts...)
	}
	if m, ok := media.(*tg.NewMessage); ok {
		return TransferDownload(m, opts...)
	}
	ctx, done := s.operation(opt.Ctx)
	defer done()
	opt.Ctx = ctx
	received, cleanup, err := s.copyDownload(ctx, media)
	if err != nil {
		return "", err
	}
	defer cleanup()
	return s.user.DownloadMedia(received.Media(), &opt)
}

func TransferDownloadChunk(ctx context.Context, m *tg.NewMessage, start, end, chunk int) ([]byte, string, error) {
	if m == nil || m.Client == nil {
		return nil, "", errors.New("missing source message")
	}
	s := transferForContext(m.Client, ctx)
	if s == nil {
		return m.Client.DownloadChunkContext(ctx, m.Media(), start, end, chunk)
	}
	ctx, done := s.operation(ctx)
	defer done()
	received, cleanup, err := s.forwardDownload(ctx, m)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()
	return s.user.DownloadChunkContext(ctx, received.Media(), start, end, chunk)
}

func transferNeedsUpload(media any) bool {
	switch v := media.(type) {
	case string:
		info, err := os.Stat(v)
		return err == nil && !info.IsDir()
	case []byte, io.Reader, tg.ReaderAtSource, *tg.ReaderAtSource:
		return true
	default:
		return false
	}
}

func prepareTransferMedia(api transferAPI, media any, name string, options *tg.UploadOptions) (any, error) {
	switch source := media.(type) {
	case tg.ReaderAtSource:
	case *tg.ReaderAtSource:
		if source == nil {
			return nil, errors.New("missing upload source")
		}
	default:
		return media, nil
	}
	upload := tg.UploadOptions{}
	if options != nil {
		upload = *options
	}
	if upload.FileName == "" {
		upload.FileName = name
	}
	if upload.Ctx != nil {
		if err := upload.Ctx.Err(); err != nil {
			return nil, err
		}
	}
	file, err := api.UploadFile(media, &upload)
	if err != nil {
		return nil, err
	}
	if upload.Ctx != nil {
		if err := upload.Ctx.Err(); err != nil {
			return nil, err
		}
	}
	return file, nil
}

func (s *FileTransfers) upload(ctx context.Context, media any, opt tg.MediaOptions) (*tg.NewMessage, func(), error) {
	upload := tg.UploadOptions{}
	if opt.Upload != nil {
		upload = *opt.Upload
	}
	upload.Ctx = ctx
	token := transferToken()
	ch, remove, err := s.subscribe(transferReceipt{true, token})
	if err != nil {
		return nil, nil, err
	}
	defer remove()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	relay := tg.MediaOptions{Caption: token, Silent: true, Upload: &upload, FileName: opt.FileName,
		ForceDocument: opt.ForceDocument, MimeType: opt.MimeType, Attributes: opt.Attributes,
		Thumb: opt.Thumb, Spoiler: opt.Spoiler, NoSoundVideo: opt.NoSoundVideo, SkipHash: opt.SkipHash}
	media, err = prepareTransferMedia(s.user, media, opt.FileName, &upload)
	if err != nil {
		return nil, nil, fmt.Errorf("upload with transfer account: %w", err)
	}
	sent, err := transferMessageCall(ctx, func() (*tg.NewMessage, error) {
		return s.user.SendMedia(s.botPeer, media, &relay)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("upload with transfer account: %w", err)
	}
	cleanup := func() { s.cleanup(s.user, s.botPeer, sent) }
	received, err := s.receipt(ctx, ch)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return received, cleanup, nil
}

func transferSendOptions(opt tg.MediaOptions) *tg.SendOptions {
	return &tg.SendOptions{ParseMode: opt.ParseMode, Entities: opt.Entities, ReplyID: opt.ReplyID,
		ReplyTo: opt.ReplyTo, TopicID: opt.TopicID, ReplyMarkup: opt.ReplyMarkup, Silent: opt.Silent,
		SendAs: opt.SendAs, NoForwards: opt.NoForwards, Spoiler: opt.Spoiler, InvertMedia: opt.InvertMedia,
		ScheduleDate: opt.ScheduleDate, Effect: opt.Effect, AllowPaidStars: opt.AllowPaidStars}
}

func TransferUploadEdit(status *tg.NewMessage, media any, opts ...*tg.MediaOptions) (*tg.NewMessage, error) {
	if status == nil || status.Client == nil {
		return nil, errors.New("missing transfer status message")
	}
	opt := transferMediaOptions(opts)
	send := transferSendOptions(opt)
	caption := opt.Caption
	if caption == nil {
		caption = ""
	}
	s := transferForContext(status.Client, mediaContext(opt))
	if s == nil || !transferNeedsUpload(media) {
		prepared, err := prepareTransferMedia(status.Client, media, opt.FileName, opt.Upload)
		if err != nil {
			return nil, err
		}
		send.Media, send.Upload = prepared, opt.Upload
		send.FileName, send.ForceDocument, send.MimeType = opt.FileName, opt.ForceDocument, opt.MimeType
		send.Attributes, send.Thumb = opt.Attributes, opt.Thumb
		var ctx context.Context
		if opt.Upload != nil {
			ctx = opt.Upload.Ctx
		}
		return deliverTransferUpload(ctx, status.Client, status, prepared, opt, send, caption)
	}
	var ctx context.Context
	if opt.Upload != nil {
		ctx = opt.Upload.Ctx
	}
	ctx, done := s.operation(ctx)
	defer done()
	if opt.Upload == nil {
		opt.Upload = &tg.UploadOptions{ProgressManager: tg.NewProgressManager(5).SetMessage(status)}
	}
	received, cleanup, err := s.upload(ctx, media, opt)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	send.Media = received.Media()
	return deliverTransferUpload(ctx, s.bot, status, received.Media(), opt, send, caption)
}

// Telegram cannot replace a text progress message with some media, including
// stickers. Send those as a new bot message using the bot's received reference.
// Keep the progress message until delivery succeeds so failures remain visible.
func deliverTransferUpload(ctx context.Context, bot transferAPI, status *tg.NewMessage, media any, opt tg.MediaOptions, send *tg.SendOptions, caption any) (*tg.NewMessage, error) {
	result, err := transferMessageCall(ctx, func() (*tg.NewMessage, error) {
		return bot.EditMessage(status.Peer, status.ID, caption, send)
	})
	if err == nil || !tg.MatchError(err, "MEDIA_NEW_INVALID") {
		return result, err
	}
	if opt.ReplyTo == nil && opt.ReplyID == 0 {
		opt.ReplyID = status.ReplyToMsgID()
	}
	if opt.TopicID == 0 && status.Message != nil {
		if reply, ok := status.Message.ReplyTo.(*tg.MessageReplyHeaderObj); ok && reply != nil {
			opt.TopicID = reply.ReplyToTopID
		}
	}
	result, err = transferMessageCall(ctx, func() (*tg.NewMessage, error) {
		return bot.SendMedia(status.Peer, media, &opt)
	})
	if err != nil {
		return nil, err
	}
	// A cleanup failure must not turn a delivered upload into a failed upload.
	if _, cleanupErr := bot.DeleteMessages(status.Peer, []int32{status.ID}); cleanupErr != nil && Client != nil {
		Client.Log.Warn("upload delivered but progress cleanup failed: %v", cleanupErr)
	}
	return result, nil
}

func TransferSendMedia(c *tg.Client, peer, media any, opts ...*tg.MediaOptions) (*tg.NewMessage, error) {
	opt := transferMediaOptions(opts)
	s := transferForContext(c, mediaContext(opt))
	if s == nil || !transferNeedsUpload(media) {
		prepared, err := prepareTransferMedia(c, media, opt.FileName, opt.Upload)
		if err != nil {
			return nil, err
		}
		return transferMessageCall(mediaContext(opt), func() (*tg.NewMessage, error) {
			return c.SendMedia(peer, prepared, opts...)
		})
	}
	status, err := c.SendMessage(peer, "Uploading...", transferSendOptions(opt))
	if err != nil {
		return nil, err
	}
	if opt.Upload == nil {
		opt.Upload = &tg.UploadOptions{ProgressManager: tg.NewProgressManager(5).SetMessage(status)}
	}
	result, err := TransferUploadEdit(status, media, &opt)
	if err != nil {
		_, _ = status.Edit("Upload failed: " + html.EscapeString(err.Error()))
	}
	return result, err
}

func TransferReplyMedia(m *tg.NewMessage, media any, opts ...*tg.MediaOptions) (*tg.NewMessage, error) {
	opt := transferMediaOptions(opts)
	opt.ReplyID = m.ID
	return TransferSendMedia(m.Client, m.ChannelID(), media, &opt)
}

func TransferRespondMedia(m *tg.NewMessage, media any, opts ...*tg.MediaOptions) (*tg.NewMessage, error) {
	return TransferSendMedia(m.Client, m.ChannelID(), media, opts...)
}

func TransferSendableMedia(c *tg.Client, media any, meta *tg.MediaMetadata) (tg.InputMedia, error) {
	if meta == nil {
		meta = &tg.MediaMetadata{}
	}
	var ctx context.Context
	if meta.Upload != nil {
		ctx = meta.Upload.Ctx
	}
	s := transferForContext(c, ctx)
	if s == nil || !transferNeedsUpload(media) {
		prepared, err := prepareTransferMedia(c, media, meta.FileName, meta.Upload)
		if err != nil {
			return nil, err
		}
		return c.GetSendableMedia(prepared, meta)
	}
	ctx, done := s.operation(ctx)
	defer done()
	received, cleanup, err := s.upload(ctx, media, tg.MediaOptions{Upload: meta.Upload, FileName: meta.FileName,
		Attributes: meta.Attributes, MimeType: meta.MimeType, ForceDocument: meta.ForceDocument,
		Thumb: meta.Thumb, Spoiler: meta.Spoiler, NoSoundVideo: meta.NoSoundVideo})
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return c.GetSendableMedia(received.Media(), meta)
}

func UserTransfersEnabled() bool { return transferService.Load() != nil }

func TransferReplyAlbum(m *tg.NewMessage, paths []string, opts ...*tg.MediaOptions) ([]*tg.NewMessage, error) {
	opt := transferMediaOptions(opts)
	s := transferForContext(m.Client, mediaContext(opt))
	if s == nil {
		return m.ReplyAlbum(paths, opts...)
	}
	opt.ReplyID = m.ID
	status, err := m.Reply("Uploading album…")
	if err != nil {
		return nil, err
	}
	ctx, done := TrackFileTransfer(status, m.SenderID())
	defer done()
	ctx, finish := s.operation(ctx)
	defer finish()
	var media []tg.InputMedia
	for _, path := range paths {
		part := opt
		part.Upload = &tg.UploadOptions{Ctx: ctx, ProgressManager: TransferProgress(status)}
		received, cleanup, err := s.upload(ctx, path, part)
		if err != nil {
			_, _ = status.Edit("Album upload failed: " + html.EscapeString(err.Error()))
			return nil, err
		}
		defer cleanup()
		input, err := m.Client.GetSendableMedia(received.Media(), nil)
		if err != nil {
			return nil, err
		}
		media = append(media, input)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := m.Client.SendAlbum(m.ChannelID(), media, &opt)
	if err == nil {
		_, _ = status.Delete()
	} else {
		_, _ = status.Edit("Album delivery failed: " + html.EscapeString(err.Error()))
	}
	return result, err
}

func TransferMediaDC(media tg.MessageMedia) int {
	switch m := media.(type) {
	case *tg.MessageMediaDocument:
		if m != nil {
			if d, ok := m.Document.(*tg.DocumentObj); ok && d != nil {
				return int(d.DcID)
			}
		}
	case *tg.MessageMediaPhoto:
		if m != nil {
			if p, ok := m.Photo.(*tg.PhotoObj); ok && p != nil {
				return int(p.DcID)
			}
		}
	}
	return 0
}

func TransferProgress(status *tg.NewMessage, fileDC ...int) *tg.ProgressManager {
	var progressMu sync.Mutex
	nextEdit := time.Now().Add(5 * time.Second)
	return tg.NewProgressManager(5).WithCallback(func(info *tg.ProgressInfo) {
		if info == nil || info.Percentage >= 100 {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		if time.Now().Before(nextEdit) {
			return
		}
		nextEdit = time.Now().Add(5 * time.Second)
		cancelMutex.RLock()
		active, exists := downloadCancels[fileTransferKey{status.ChatID(), status.ID}]
		cancelMutex.RUnlock()
		if exists && active.ctx.Err() != nil {
			return
		}
		client := status.Client
		if s := transferForContext(status.Client, active.ctx); exists && s != nil {
			if user, ok := s.user.(*tg.Client); ok {
				client = user
			}
		}
		dc, dcLabel := client.GetDC(), "Upload DC"
		if len(fileDC) > 0 {
			dc, dcLabel = fileDC[0], "File DC"
		}
		dcText := "unknown"
		if dc > 0 {
			dcText = fmt.Sprintf("DC%d", dc)
		}
		text := fmt.Sprintf("<b>Name:</b> %s\n<b>%s:</b> %s\n<b>Size:</b> %.2f MiB\n<b>Speed:</b> %s\n<b>ETA:</b> %s | <b>Elapsed:</b> %s\n\n%.2f%%",
			transferCaption(info.FileName), dcLabel, dcText, float64(info.TotalSize)/1024/1024, info.SpeedString(), info.ETAString(), info.ElapsedString(), info.Percentage)
		if info.Phase == "finalizing" {
			text += "\nFinalizing file…"
		}
		opt := &tg.SendOptions{ParseMode: tg.HTML}
		if exists {
			opt.ReplyMarkup = transferCancelKeyboard(status.ID)
		}
		if _, err := status.Edit(text, opt); err != nil {
			if wait := tg.GetFloodWait(err); wait > 0 {
				nextEdit = time.Now().Add(max(5*time.Second, time.Duration(wait)*time.Second+250*time.Millisecond))
			}
		}
		for _, stat := range client.GetTransferStats() {
			client.Log.Info("transfer dc=%d upload=%v requests=%d failed=%d floods=%d active=%d concurrency=%d",
				stat.DC, stat.Upload, stat.Requests, stat.FailedRequests, stat.FloodWaits, stat.Active, stat.Concurrency)
		}
	})
}

func transferCaption(name string) string {
	return "<code>" + html.EscapeString(strings.TrimSpace(name)) + "</code>"
}
