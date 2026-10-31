package extras

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"main/internal/kisskh"
	"main/modules"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

type kissPicker struct {
	mu      sync.Mutex
	owner   int64
	created time.Time
	status  *tg.NewMessage
	results []kisskh.Drama
	drama   *kisskh.Drama
}

var kissPickers sync.Map
var kissJobs = make(chan struct{}, 1)
var kissAPI = kisskh.New()

const kissPageSize = 24

func kissKeyboard(key string, drama *kisskh.Drama, page int) *tg.ReplyInlineMarkup {
	kb := tg.NewKeyboard()
	start := page * kissPageSize
	end := min(start+kissPageSize, len(drama.Episodes))
	for i := start; i < end; i += 4 {
		row := []tg.KeyboardInlineButton{}
		for j := i; j < min(i+4, end); j++ {
			e := drama.Episodes[j]
			row = append(row, tg.Button.Data(fmt.Sprintf("Ep %g", e.Number), fmt.Sprintf("kk:%s:ep:%d", key, e.ID)))
		}
		kb.AddRow(row...)
	}
	row := []tg.KeyboardInlineButton{}
	if page > 0 {
		row = append(row, tg.Button.Data("Previous", fmt.Sprintf("kk:%s:page:%d", key, page-1)))
	}
	if end < len(drama.Episodes) {
		row = append(row, tg.Button.Data("Next", fmt.Sprintf("kk:%s:page:%d", key, page+1)))
	}
	if len(row) > 0 {
		kb.AddRow(row...)
	}
	kb.AddRow(tg.Button.Data("Close", "kk:"+key+":close:0"))
	return kb.Build()
}
func kissText(d *kisskh.Drama) string {
	desc := []rune(d.Description)
	if len(desc) > 800 {
		desc = append(desc[:800], []rune("…")...)
	}
	return fmt.Sprintf("<b>%s</b>\n%s · %d episodes\n\n%s\n\nChoose an episode. All available subtitles will be embedded as selectable tracks.", html.EscapeString(d.Title), html.EscapeString(d.Status), len(d.Episodes), html.EscapeString(string(desc)))
}
func KissKHHandler(m *tg.NewMessage) error {
	query := strings.TrimSpace(m.Args())
	if query == "" {
		_, e := m.Reply("Usage: <code>/kisskh &lt;drama ID, name or URL&gt;</code>")
		return e
	}
	status, e := m.Reply("Looking up KissKH…")
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s := &kissPicker{owner: m.SenderID(), created: time.Now(), status: status}
	if id, ok := kisskh.DramaID(query); ok {
		s.drama, e = kissAPI.Drama(ctx, id)
	} else {
		s.results, e = kissAPI.Search(ctx, query)
	}
	if e != nil {
		_, e = status.Edit("KissKH lookup failed: " + html.EscapeString(e.Error()))
		return e
	}
	var raw [8]byte
	if _, e = rand.Read(raw[:]); e != nil {
		return e
	}
	key := hex.EncodeToString(raw[:])
	kissPickers.Range(func(k, v any) bool {
		if time.Since(v.(*kissPicker).created) > time.Hour {
			kissPickers.Delete(k)
		}
		return true
	})
	kissPickers.Store(key, s)
	if s.drama != nil {
		_, e = status.Edit(kissText(s.drama), &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: kissKeyboard(key, s.drama, 0)})
		return e
	}
	if len(s.results) == 0 {
		kissPickers.Delete(key)
		_, e = status.Edit("No matching dramas found.")
		return e
	}
	kb := tg.NewKeyboard()
	if len(s.results) > 20 {
		s.results = s.results[:20]
	}
	for _, d := range s.results {
		kb.AddRow(tg.Button.Data(d.Title, fmt.Sprintf("kk:%s:show:%d", key, d.ID)))
	}
	_, e = status.Edit("Choose a drama (top 20 matches):", &tg.SendOptions{ReplyMarkup: kb.Build()})
	return e
}
func KissKHCallback(q *tg.CallbackQuery) error {
	parts := strings.Split(q.DataString(), ":")
	if len(parts) != 4 {
		return nil
	}
	v, ok := kissPickers.Load(parts[1])
	if !ok {
		_, e := q.Answer("Picker expired. Run /kisskh again.", &tg.CallbackOptions{Alert: true})
		return e
	}
	s := v.(*kissPicker)
	if q.SenderID != s.owner || q.ChatID != s.status.ChatID() || q.MessageID != s.status.ID {
		_, e := q.Answer("This picker belongs to another request.", &tg.CallbackOptions{Alert: true})
		return e
	}
	if time.Since(s.created) > time.Hour {
		kissPickers.Delete(parts[1])
		_, e := q.Answer("Picker expired. Run /kisskh again.")
		return e
	}
	if !s.mu.TryLock() {
		_, e := q.Answer("Please wait…")
		return e
	}
	defer s.mu.Unlock()
	n, e := strconv.ParseInt(parts[3], 10, 64)
	if e != nil {
		return nil
	}
	switch parts[2] {
	case "close":
		kissPickers.Delete(parts[1])
		_, _ = q.Answer("")
		_, e = q.Edit("Picker closed.")
		return e
	case "show":
		found := false
		for _, d := range s.results {
			if d.ID == n {
				found = true
			}
		}
		if !found {
			return nil
		}
		_, _ = q.Answer("Loading episodes…")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		s.drama, e = kissAPI.Drama(ctx, n)
		if e != nil {
			_, e = q.Edit("KissKH lookup failed: " + html.EscapeString(e.Error()))
			return e
		}
		_, e = q.Edit(kissText(s.drama), &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: kissKeyboard(parts[1], s.drama, 0)})
		return e
	case "page":
		if s.drama == nil || n < 0 || n >= int64((len(s.drama.Episodes)+kissPageSize-1)/kissPageSize) {
			return nil
		}
		_, _ = q.Answer("")
		_, e = q.Edit(kissText(s.drama), &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: kissKeyboard(parts[1], s.drama, int(n))})
		return e
	case "ep":
		if s.drama == nil {
			return nil
		}
		var ep kisskh.Episode
		for _, candidate := range s.drama.Episodes {
			if candidate.ID == n {
				ep = candidate
			}
		}
		if ep.ID == 0 {
			return nil
		}
		select {
		case kissJobs <- struct{}{}:
		default:
			_, e = q.Answer("An episode is already downloading. Please try again when it finishes.", &tg.CallbackOptions{Alert: true})
			return e
		}
		_, _ = q.Answer(fmt.Sprintf("Preparing episode %g…", ep.Number))
		drama := *s.drama
		go func() { defer func() { <-kissJobs }(); runKissDownload(s.status, s.owner, drama, ep) }()
	}
	return nil
}
func runKissDownload(picker *tg.NewMessage, owner int64, drama kisskh.Drama, ep kisskh.Episode) {
	status, e := picker.Reply(fmt.Sprintf("Preparing %s - episode %g...", html.EscapeString(drama.Title), ep.Number))
	if e != nil {
		return
	}
	ctx, done := modules.TrackUserFileTransfer(status, owner)
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	_, e = deliverKissEpisode(ctx, status, drama, ep, nil)
	if e != nil {
		text := "KissKH download failed: " + e.Error()
		if ctx.Err() != nil {
			text = "KissKH download cancelled or timed out."
		}
		if len(text) > 2000 {
			text = text[:2000]
		}
		_, _ = status.Edit(html.EscapeString(text), &tg.SendOptions{ParseMode: tg.HTML})
	}
}

// Both interactive and scheduled uploads use the same subtitle, poster and user-account relay path.
func deliverKissEpisode(ctx context.Context, status *tg.NewMessage, drama kisskh.Drama, ep kisskh.Episode, beforeUpload func() error) (*tg.NewMessage, error) {
	update := func(text string) {
		if beforeUpload == nil {
			modules.UpdateFileTransferStatus(status, text)
		} else {
			_, _ = status.Edit(text, &tg.SendOptions{ParseMode: tg.HTML})
		}
	}
	dir, e := os.MkdirTemp("", "kisskh-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(dir)
	limits, e := modules.TransferUploadLimits(ctx, status.Client)
	if e != nil {
		return nil, e
	}
	update("Resolving video and decrypting all subtitle tracks...")
	source, e := kissAPI.Resolve(ctx, ep.ID)
	if e != nil {
		return nil, e
	}
	filename := fmt.Sprintf("%s - E%02g.mp4", sanitizeFileName(drama.Title), ep.Number)
	file, meta, e := kisskh.Download(ctx, source, dir, filename, limits.MaxFileSize, func(stage string) { update(html.EscapeString(stage)) })
	if e != nil {
		return nil, e
	}
	thumb := filepath.Join(dir, "thumb.jpg")
	if e = kissAPI.PosterThumbnail(ctx, drama.Thumbnail, thumb); e != nil {
		if e = kisskh.Thumbnail(ctx, file, thumb); e != nil {
			return nil, e
		}
	}
	labels := []string{}
	for _, sub := range source.Subtitles {
		labels = append(labels, sub.Label)
	}
	caption := fmt.Sprintf("<b>%s - Episode %g</b>\n%d x %d | %s\nSubtitles: %s", html.EscapeString(drama.Title), ep.Number, meta.Width, meta.Height, (time.Duration(meta.Duration) * time.Second).String(), html.EscapeString(strings.Join(labels, ", ")))
	if beforeUpload != nil {
		if e = beforeUpload(); e != nil {
			return nil, e
		}
	}
	update("Uploading video with subtitles...")
	return modules.TransferUploadEdit(status, file, &tg.MediaOptions{Caption: caption, ParseMode: tg.HTML, FileName: filename, ForceDocument: true, MimeType: "video/mp4", Thumb: thumb, Attributes: []tg.DocumentAttribute{&tg.DocumentAttributeFilename{FileName: filename}, &tg.DocumentAttributeVideo{W: int32(meta.Width), H: int32(meta.Height), Duration: meta.Duration, SupportsStreaming: true}}, Upload: &tg.UploadOptions{Ctx: ctx, ProgressManager: modules.TransferProgress(status)}})
}
func init() {
	modules.Mods.AddModule("KissKH", "<b>KissKH</b>\n/kisskh &lt;drama ID, name or URL&gt; — choose an episode to download.\nEpisodes are shown four per row. Videos include all available selectable subtitle tracks and are sent as MP4 files. Use a player such as VLC to select subtitle languages.\nPublic downloads are available to everyone. Uploads use the configured transfer account when available; final delivery is by the bot.\nAdmins: /kisswatch add &lt;drama&gt;, /kisswatch list, /kisswatch remove &lt;ID&gt;, /kisschannel &lt;channel&gt;. One shared watchlist checks every 30 minutes and skips existing episodes when added.")
	modules.QueueHandlerRegistration(func() {
		modules.OnCommand(modules.Client, "cmd:kisskh", KissKHHandler)
		modules.Client.On("callback:kk:", KissKHCallback)
	})
}
