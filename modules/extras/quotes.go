package extras

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	modules "main/modules"
	"main/modules/db"

	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
)

var quotesBucket = []byte("quotes")

type quoteRecord struct {
	ID          uint64 `json:"id"`
	ChatID      int64  `json:"chat_id"`
	UserID      int64  `json:"user_id"`
	UserName    string `json:"user_name"`
	UserHandle  string `json:"user_handle"`
	Text        string `json:"text"`
	SavedBy     int64  `json:"saved_by"`
	SavedByName string `json:"saved_by_name"`
	Timestamp   int64  `json:"ts"`
}

func quoteAPIBase() string {
	if v := strings.TrimSuffix(strings.TrimSpace(os.Getenv("QUOTE_API")), "/"); v != "" {
		return v
	}
	return "https://quote.yuri.ly"
}

const (
	avatarCacheTTL   = 6 * time.Hour
	avatarCacheDir   = "tmp/avatars"
	avatarNoneMarker = ".none"
)

var (
	avatarClient   *tg.Client
	avatarClientMu sync.RWMutex
)

func AvatarServerInit(c *tg.Client) {
	avatarClientMu.Lock()
	avatarClient = c
	avatarClientMu.Unlock()
	_ = os.MkdirAll(avatarCacheDir, 0o755)
	http.HandleFunc("/avatar/", avatarServeHTTP)
}

// avatarSelfURL returns where the renderer can reach /avatar/, or "" when it can't
// (the default remote renderer cannot see this dyno's localhost server).
func avatarSelfURL() string {
	if v := strings.TrimSuffix(strings.TrimSpace(os.Getenv("BOT_PUBLIC_URL")), "/"); v != "" {
		return v
	}
	if quoteAPIIsLocal(quoteAPIBase()) {
		return "http://localhost:6060"
	}
	return ""
}

func quoteAPIIsLocal(base string) bool {
	return strings.Contains(base, "://localhost") || strings.Contains(base, "://127.0.0.1")
}

func quoteAvatarURL(username string, uid int64) string {
	if username != "" {
		return fmt.Sprintf("https://t.me/i/userpic/320/%s.jpg", username)
	}
	if self := avatarSelfURL(); self != "" {
		return fmt.Sprintf("%s/avatar/%d.jpg", self, uid)
	}
	return ""
}

func avatarServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/avatar/")
	name = strings.TrimSuffix(name, ".jpg")
	uid, err := strconv.ParseInt(name, 10, 64)
	if err != nil || uid == 0 {
		http.NotFound(w, r)
		return
	}

	cached := filepath.Join(avatarCacheDir, fmt.Sprintf("%d.jpg", uid))
	miss := filepath.Join(avatarCacheDir, fmt.Sprintf("%d%s", uid, avatarNoneMarker))

	if st, err := os.Stat(cached); err == nil && time.Since(st.ModTime()) < avatarCacheTTL {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, cached)
		return
	}
	if st, err := os.Stat(miss); err == nil && time.Since(st.ModTime()) < avatarCacheTTL {
		http.NotFound(w, r)
		return
	}

	avatarClientMu.RLock()
	c := avatarClient
	avatarClientMu.RUnlock()
	if c == nil {
		http.Error(w, "bot not ready", http.StatusServiceUnavailable)
		return
	}

	u, err := c.GetUser(uid)
	if err != nil || u == nil || u.Photo == nil {
		_ = os.WriteFile(miss, nil, 0o644)
		http.NotFound(w, r)
		return
	}
	full, err := c.UsersGetFullUser(&tg.InputUserObj{UserID: uid, AccessHash: u.AccessHash})
	if err != nil || full == nil {
		_ = os.WriteFile(miss, nil, 0o644)
		http.NotFound(w, r)
		return
	}
	var photo tg.Photo
	if full.FullUser.ProfilePhoto != nil {
		photo = full.FullUser.ProfilePhoto
	} else if full.FullUser.PersonalPhoto != nil {
		photo = full.FullUser.PersonalPhoto
	} else if full.FullUser.FallbackPhoto != nil {
		photo = full.FullUser.FallbackPhoto
	}
	p, ok := photo.(*tg.PhotoObj)
	if !ok || p == nil {
		_ = os.WriteFile(miss, nil, 0o644)
		http.NotFound(w, r)
		return
	}
	if _, err := modules.TransferDownloadMedia(c, p, &tg.DownloadOptions{FileName: cached}); err != nil {
		os.Remove(cached)
		http.Error(w, "download failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeFile(w, r, cached)
}

type qaEntity struct {
	Type   string `json:"type"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	URL    string `json:"url,omitempty"`
	UserID int64  `json:"user_id,omitempty"`
}

type qaPhoto struct {
	URL string `json:"url,omitempty"`
}

type qaFrom struct {
	ID          int64    `json:"id"`
	FirstName   string   `json:"first_name,omitempty"`
	LastName    string   `json:"last_name,omitempty"`
	Name        string   `json:"name,omitempty"`
	Username    string   `json:"username,omitempty"`
	Title       string   `json:"title,omitempty"`
	EmojiStatus string   `json:"emoji_status,omitempty"`
	IsPremium   bool     `json:"is_premium,omitempty"`
	IsVerified  bool     `json:"is_verified,omitempty"`
	IsBot       bool     `json:"is_bot,omitempty"`
	Photo       *qaPhoto `json:"photo,omitempty"`
}

type qaReplyMessage struct {
	Name     string     `json:"name,omitempty"`
	Text     string     `json:"text,omitempty"`
	Entities []qaEntity `json:"entities,omitempty"`
	ChatID   int64      `json:"chatId,omitempty"`
	From     *qaFrom    `json:"from,omitempty"`
}

type qaForward struct {
	Label string `json:"label,omitempty"`
}

type qaMessage struct {
	From         qaFrom          `json:"from"`
	Text         string          `json:"text"`
	Entities     []qaEntity      `json:"entities,omitempty"`
	Avatar       bool            `json:"avatar"`
	ReplyMessage *qaReplyMessage `json:"replyMessage,omitempty"`
	Forward      *qaForward      `json:"forward,omitempty"`
	ViaBot       string          `json:"viaBot,omitempty"`
	SenderTag    string          `json:"senderTag,omitempty"`
	IsQuote      bool            `json:"isQuote,omitempty"`
}

type qaRequest struct {
	Type            string      `json:"type,omitempty"`
	Format          string      `json:"format,omitempty"`
	Ext             string      `json:"ext,omitempty"`
	BackgroundColor string      `json:"backgroundColor,omitempty"`
	Width           int         `json:"width,omitempty"`
	Height          int         `json:"height,omitempty"`
	Scale           int         `json:"scale,omitempty"`
	EmojiBrand      string      `json:"emojiBrand,omitempty"`
	Messages        []qaMessage `json:"messages"`
}

func quoteEntityType(e tg.MessageEntity) (string, string, int64) {
	switch e.(type) {
	case *tg.MessageEntityBold:
		return "bold", "", 0
	case *tg.MessageEntityItalic:
		return "italic", "", 0
	case *tg.MessageEntityUnderline:
		return "underline", "", 0
	case *tg.MessageEntityStrike:
		return "strikethrough", "", 0
	case *tg.MessageEntitySpoiler:
		return "spoiler", "", 0
	case *tg.MessageEntityCode:
		return "code", "", 0
	case *tg.MessageEntityPre:
		return "pre", "", 0
	case *tg.MessageEntityBlockquote:
		return "blockquote", "", 0
	case *tg.MessageEntityBotCommand:
		return "bot_command", "", 0
	case *tg.MessageEntityURL:
		return "url", "", 0
	case *tg.MessageEntityMention:
		return "mention", "", 0
	case *tg.MessageEntityHashtag:
		return "hashtag", "", 0
	case *tg.MessageEntityCashtag:
		return "cashtag", "", 0
	case *tg.MessageEntityEmail:
		return "email", "", 0
	case *tg.MessageEntityPhone:
		return "phone_number", "", 0
	case *tg.MessageEntityTextURL:
		if v, ok := e.(*tg.MessageEntityTextURL); ok {
			return "text_link", v.URL, 0
		}
	case *tg.MessageEntityMentionName:
		if v, ok := e.(*tg.MessageEntityMentionName); ok {
			return "text_mention", "", v.UserID
		}
	case *tg.MessageEntityCustomEmoji:
		return "", "", 0
	}
	return "", "", 0
}

func quoteBuildEntities(src []tg.MessageEntity) []qaEntity {
	if len(src) == 0 {
		return nil
	}
	out := make([]qaEntity, 0, len(src))
	for _, e := range src {
		var (
			offset, length int32
			t              string
			url            string
			uid            int64
		)
		switch v := e.(type) {
		case *tg.MessageEntityBold:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityItalic:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityUnderline:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityStrike:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntitySpoiler:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityCode:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityPre:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityBlockquote:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityBotCommand:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityURL:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityMention:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityHashtag:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityCashtag:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityEmail:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityPhone:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityTextURL:
			offset, length = v.Offset, v.Length
		case *tg.MessageEntityMentionName:
			offset, length = v.Offset, v.Length
		}
		t, url, uid = quoteEntityType(e)
		if t == "" {
			continue
		}
		out = append(out, qaEntity{
			Type:   t,
			Offset: int(offset),
			Length: int(length),
			URL:    url,
			UserID: uid,
		})
	}
	return out
}

func quoteResolveFrom(c *tg.Client, senderID, chatID int64) qaFrom {
	f := qaFrom{ID: senderID}
	if senderID == 0 {
		f.Name = "User"
		return f
	}
	u, err := c.GetUser(senderID)
	if err != nil || u == nil {
		f.Name = fmt.Sprintf("User %d", senderID)
		return f
	}
	f.FirstName = u.FirstName
	f.LastName = u.LastName
	f.Username = u.Username
	f.IsPremium = u.Premium
	f.IsVerified = u.Verified
	f.IsBot = u.Bot
	if u.Photo != nil {
		if p, ok := u.Photo.(*tg.UserProfilePhotoObj); ok && p != nil && p.PhotoID != 0 {
			if url := quoteAvatarURL(u.Username, senderID); url != "" {
				f.Photo = &qaPhoto{URL: url}
			}
		}
	}
	if es, ok := u.EmojiStatus.(*tg.EmojiStatusObj); ok && es.DocumentID != 0 {
		f.EmojiStatus = strconv.FormatInt(es.DocumentID, 10)
	} else if esc, ok := u.EmojiStatus.(*tg.EmojiStatusCollectible); ok && esc.DocumentID != 0 {
		f.EmojiStatus = strconv.FormatInt(esc.DocumentID, 10)
	}
	if strings.TrimSpace(f.FirstName+f.LastName) == "" {
		if u.Username != "" {
			f.Name = "@" + u.Username
		} else {
			f.Name = fmt.Sprintf("User %d", senderID)
		}
	}
	if chatID != 0 && !u.Bot {
		if part, perr := c.GetChatMember(chatID, senderID); perr == nil && part != nil {
			if part.Rank != "" {
				f.Title = part.Rank
			} else if part.Status == tg.Creator {
				f.Title = "Owner"
			} else if part.Status == tg.Admin {
				f.Title = "Admin"
			}
		}
	}
	return f
}

func quoteBuildMessage(client *tg.Client, msg *tg.NewMessage, chatID int64, includeReply bool) qaMessage {
	from := quoteResolveFrom(client, msg.SenderID(), chatID)
	out := qaMessage{
		From:      from,
		Text:      msg.RawText(),
		Avatar:    true,
		SenderTag: from.Title,
	}
	if msg.Message != nil {
		out.Entities = quoteBuildEntities(msg.Message.Entities)
		if msg.Message.ViaBotID != 0 {
			if u, err := client.GetUser(msg.Message.ViaBotID); err == nil && u != nil && u.Username != "" {
				out.ViaBot = "@" + u.Username
			}
		}
		if fh := msg.Message.FwdFrom; fh != nil {
			label := ""
			switch fp := fh.FromID.(type) {
			case *tg.PeerUser:
				if u, err := client.GetUser(fp.UserID); err == nil && u != nil {
					label = strings.TrimSpace(u.FirstName + " " + u.LastName)
					if label == "" && u.Username != "" {
						label = "@" + u.Username
					}
				}
			case *tg.PeerChannel:
				if ch, err := client.GetChannel(fp.ChannelID); err == nil && ch != nil {
					label = ch.Title
				}
			case *tg.PeerChat:
				if ch, err := client.GetChat(fp.ChatID); err == nil && ch != nil {
					label = ch.Title
				}
			}
			if label == "" && fh.FromName != "" {
				label = fh.FromName
			}
			if label != "" {
				out.Forward = &qaForward{Label: label}
			}
		}
	}
	if !includeReply || !msg.IsReply() {
		return out
	}
	prev, err := msg.GetReplyMessage()
	if err != nil || prev == nil {
		return out
	}
	prevFrom := quoteResolveFrom(client, prev.SenderID(), chatID)
	prevName := strings.TrimSpace(prevFrom.FirstName + " " + prevFrom.LastName)
	if prevName == "" {
		prevName = prevFrom.Name
	}
	if prevName == "" {
		prevName = "User"
	}
	rm := &qaReplyMessage{
		Name:   prevName,
		Text:   prev.RawText(),
		ChatID: chatID,
		From:   &prevFrom,
	}
	if prev.Message != nil {
		rm.Entities = quoteBuildEntities(prev.Message.Entities)
	}
	if strings.TrimSpace(rm.Text) == "" && len(rm.Entities) == 0 {
		return out
	}
	out.ReplyMessage = rm
	return out
}

const quoteMaxImage = 15 << 20

// quoteRequestImage returns the rendered image and whether it is PNG (detected from
// magic bytes; the renderer may answer .png requests with WebP).
func quoteRequestImage(req qaRequest, wantPNG bool) ([]byte, bool, error) {
	endpoint := "/generate.webp"
	if wantPNG {
		endpoint = "/generate.png"
		req.Ext = "png"
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	data, err := extFetch(ctx, http.MethodPost, quoteAPIBase()+endpoint, bytes.NewReader(body), quoteMaxImage, "Content-Type", "application/json")
	if err != nil {
		return nil, false, fmt.Errorf("quote renderer: %w", err)
	}
	switch {
	case bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G'}):
		return data, true, nil
	case len(data) > 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return data, false, nil
	}
	var errResp struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(data, &errResp) == nil && errResp.Error != nil {
		return nil, false, fmt.Errorf("quote renderer: %v", errResp.Error)
	}
	return nil, false, fmt.Errorf("quote renderer returned an unknown format")
}

type quoteFlags struct {
	IncludeReply bool
	N            int
	ImageMode    bool
	HD           bool
	IsQuote      bool
	Brand        string
	Scale        int
	Bg           string
}

func quoteParseFlags(args string) quoteFlags {
	f := quoteFlags{}
	for _, tok := range strings.Fields(args) {
		lower := strings.ToLower(tok)
		switch {
		case lower == "r":
			f.IncludeReply = true
		case lower == "p":
			f.ImageMode = true
		case lower == "hd":
			f.HD = true
		case lower == "q":
			f.IsQuote = true
		case strings.HasPrefix(lower, "brand="):
			f.Brand = strings.TrimPrefix(lower, "brand=")
		case strings.HasPrefix(lower, "scale="):
			if n, err := strconv.Atoi(strings.TrimPrefix(lower, "scale=")); err == nil && n >= 1 && n <= 10 {
				f.Scale = n
			}
		default:
			if n, err := strconv.Atoi(tok); err == nil && n >= 1 && n <= 10 {
				f.N = n
			} else if f.Bg == "" {
				f.Bg = tok
			}
		}
	}
	return f
}

func quoteCollectMessages(client *tg.Client, m *tg.NewMessage, target *tg.NewMessage, flags quoteFlags) []qaMessage {
	chatID := m.ChatID()
	messages := []qaMessage{quoteBuildMessage(client, target, chatID, flags.IncludeReply)}
	if flags.IsQuote {
		messages[0].IsQuote = true
	}
	if flags.N <= 1 {
		return messages
	}
	history, err := client.GetMessages(chatID, &tg.SearchOption{
		MaxID: target.ID,
		Limit: int32(flags.N - 1),
	})
	if err != nil || len(history) == 0 {
		return messages
	}
	extra := make([]qaMessage, 0, len(history))
	for i := range history {
		older := &history[i]
		if older.ID == target.ID {
			continue
		}
		if strings.TrimSpace(older.RawText()) == "" {
			continue
		}
		bm := quoteBuildMessage(client, older, chatID, false)
		if flags.IsQuote {
			bm.IsQuote = true
		}
		extra = append(extra, bm)
	}
	all := make([]qaMessage, 0, len(extra)+len(messages))
	for i := len(extra) - 1; i >= 0; i-- {
		all = append(all, extra[i])
	}
	all = append(all, messages...)
	return all
}

func quoteRateBucket() []byte  { return []byte("quote_rate") }
func quoteVotesBucket() []byte { return []byte("quote_votes") }
func quotePacksBucket() []byte { return []byte("quote_packs_by_chat") }

func quoteRateIsOn(chatID int64) bool {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return false
	}
	on := false
	_ = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket(quoteRateBucket())
		if b == nil {
			return nil
		}
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, uint64(chatID))
		v := b.Get(key)
		if len(v) == 1 && v[0] == 1 {
			on = true
		}
		return nil
	})
	return on
}

func quoteRateSet(chatID int64, on bool) error {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return fmt.Errorf("db unavailable")
	}
	return d.Update(func(tx *mongostore.Tx) error {
		b, e := tx.CreateBucketIfNotExists(quoteRateBucket())
		if e != nil {
			return e
		}
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, uint64(chatID))
		val := []byte{0}
		if on {
			val = []byte{1}
		}
		return b.Put(key, val)
	})
}

type quoteVoteRecord struct {
	ChatID     int64          `json:"chat_id"`
	QuoteID    uint64         `json:"quote_id"`
	Up         map[int64]bool `json:"up"`
	Down       map[int64]bool `json:"down"`
	QuoterID   int64          `json:"quoter_id"`
	QuoterName string         `json:"quoter_name"`
	QuotedID   int64          `json:"quoted_id"`
	QuotedName string         `json:"quoted_name"`
	Preview    string         `json:"preview"`
	MessageID  int32          `json:"message_id"`
	Timestamp  int64          `json:"ts"`
}

var quoteVoteMu sync.Mutex

func quoteVoteKey(chatID int64, quoteID uint64) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], uint64(chatID))
	binary.BigEndian.PutUint64(b[8:16], quoteID)
	return b
}

func quoteVoteGet(chatID int64, quoteID uint64) *quoteVoteRecord {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return nil
	}
	var rec quoteVoteRecord
	found := false
	_ = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket(quoteVotesBucket())
		if b == nil {
			return nil
		}
		raw := b.Get(quoteVoteKey(chatID, quoteID))
		if raw == nil {
			return nil
		}
		if jerr := json.Unmarshal(raw, &rec); jerr == nil {
			found = true
			if rec.Up == nil {
				rec.Up = map[int64]bool{}
			}
			if rec.Down == nil {
				rec.Down = map[int64]bool{}
			}
		}
		return nil
	})
	if !found {
		return nil
	}
	return &rec
}

func quoteVoteSave(rec *quoteVoteRecord) error {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return fmt.Errorf("db unavailable")
	}
	return d.Update(func(tx *mongostore.Tx) error {
		b, e := tx.CreateBucketIfNotExists(quoteVotesBucket())
		if e != nil {
			return e
		}
		raw, jerr := json.Marshal(rec)
		if jerr != nil {
			return jerr
		}
		return b.Put(quoteVoteKey(rec.ChatID, rec.QuoteID), raw)
	})
}

func quoteVoteKeyboard(chatID int64, quoteID uint64, up, down int) *tg.ReplyInlineMarkup {
	upBtn := tg.Button.Data(fmt.Sprintf("👍 %d", up), fmt.Sprintf("qvote:%d:up", quoteID))
	downBtn := tg.Button.Data(fmt.Sprintf("👎 %d", down), fmt.Sprintf("qvote:%d:down", quoteID))
	return tg.NewKeyboard().AddRow(upBtn, downBtn).Build()
}

func quoteBuildRequest(m *tg.NewMessage, target *tg.NewMessage, flags quoteFlags) qaRequest {
	scale := 2
	if flags.HD {
		scale = 5
	}
	if flags.Scale > 0 {
		scale = flags.Scale
	}
	req := qaRequest{
		BackgroundColor: cmp.Or(flags.Bg, "#1b1429"),
		Width:           512,
		Height:          768,
		Scale:           scale,
		EmojiBrand:      cmp.Or(flags.Brand, "apple"),
		Messages:        quoteCollectMessages(m.Client, m, target, flags),
	}
	if flags.ImageMode {
		req.Type = "image"
	}
	return req
}

func quoteStatus(m, status *tg.NewMessage, text string) {
	if status != nil {
		if _, err := status.Edit(text); err == nil {
			return
		}
	}
	m.Reply(text)
}

func quoteRenderCore(m *tg.NewMessage, target *tg.NewMessage, flags quoteFlags) error {
	if strings.TrimSpace(target.RawText()) == "" {
		m.Reply("<b>Nothing to quote.</b> Reply to a text message.")
		return nil
	}

	status, _ := m.Reply("<i>painting your quote...</i>")

	data, isPNG, rerr := quoteRequestImage(quoteBuildRequest(m, target, flags), flags.ImageMode || flags.HD)
	if rerr != nil {
		quoteStatus(m, status, "<b>Quote failed:</b> "+html.EscapeString(rerr.Error()))
		return nil
	}

	ext, mime := ".webp", "image/webp"
	if isPNG {
		ext, mime = ".png", "image/png"
	}
	outPath := filepath.Join(os.TempDir(), fmt.Sprintf("quote_%d%s", time.Now().UnixNano(), ext))
	if werr := os.WriteFile(outPath, data, 0o644); werr != nil {
		quoteStatus(m, status, "<b>Quote failed:</b> "+html.EscapeString(werr.Error()))
		return nil
	}
	defer os.Remove(outPath)

	quotedID, quotedName := quoteExtractQuoted(m.Client, target)
	quoteID, _ := quoteAutoSave(m, target, quotedID, quotedName)

	opts := &tg.MediaOptions{
		FileName: "quote" + ext,
		MimeType: mime,
	}
	if !isPNG {
		opts.Attributes = []tg.DocumentAttribute{
			&tg.DocumentAttributeSticker{
				Alt:        "💬",
				Stickerset: &tg.InputStickerSetEmpty{},
			},
			&tg.DocumentAttributeFilename{FileName: "quote.webp"},
		}
	}
	if quoteID != 0 && quoteRateIsOn(m.ChatID()) {
		opts.ReplyMarkup = quoteVoteKeyboard(m.ChatID(), quoteID, 0, 0)
	}

	sent, merr := modules.TransferReplyMedia(m, outPath, opts)
	if merr != nil {
		quoteStatus(m, status, "<b>Upload failed:</b> "+html.EscapeString(merr.Error()))
		return nil
	}
	if sent != nil && quoteID != 0 {
		rec := &quoteVoteRecord{
			ChatID:     m.ChatID(),
			QuoteID:    quoteID,
			Up:         map[int64]bool{},
			Down:       map[int64]bool{},
			QuoterID:   m.SenderID(),
			QuoterName: quoteSenderName(m),
			QuotedID:   quotedID,
			QuotedName: quotedName,
			Preview:    quotePreview(target.RawText()),
			MessageID:  sent.ID,
			Timestamp:  time.Now().Unix(),
		}
		_ = quoteVoteSave(rec)
	}
	if status != nil {
		status.Delete()
	}
	return nil
}

func quoteExtractQuoted(client *tg.Client, target *tg.NewMessage) (int64, string) {
	if target == nil {
		return 0, ""
	}
	uid := target.SenderID()
	if uid == 0 {
		return 0, "User"
	}
	u, err := client.GetUser(uid)
	if err != nil || u == nil {
		return uid, fmt.Sprintf("User %d", uid)
	}
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name == "" {
		if u.Username != "" {
			name = "@" + u.Username
		} else {
			name = fmt.Sprintf("User %d", uid)
		}
	}
	return uid, name
}

func quoteSenderName(m *tg.NewMessage) string {
	if m.Sender == nil {
		return "User"
	}
	name := strings.TrimSpace(m.Sender.FirstName + " " + m.Sender.LastName)
	if name == "" {
		if m.Sender.Username != "" {
			name = "@" + m.Sender.Username
		} else {
			name = "User"
		}
	}
	return name
}

func quotePreview(text string) string {
	text = strings.TrimSpace(text)
	return quoteTrunc(text, 120)
}

func quoteClip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func quoteTrunc(s string, n int) string {
	if c := quoteClip(s, n); c != s {
		return c + "..."
	}
	return s
}

func quoteAutoSave(m *tg.NewMessage, target *tg.NewMessage, quotedID int64, quotedName string) (uint64, error) {
	text := strings.TrimSpace(target.RawText())
	if text == "" {
		return 0, nil
	}
	text = quoteClip(text, 4000)
	if err := quotesEnsureBucket(); err != nil {
		return 0, err
	}
	d, err := db.GetDB()
	if err != nil || d == nil {
		return 0, fmt.Errorf("db unavailable")
	}
	handle := ""
	if u, uerr := m.Client.GetUser(quotedID); uerr == nil && u != nil {
		handle = u.Username
	}
	savedByName := quoteSenderName(m)
	var newID uint64
	werr := d.Update(func(tx *mongostore.Tx) error {
		b, e := tx.CreateBucketIfNotExists(quotesBucket)
		if e != nil {
			return e
		}
		newID = quotesNextID(tx, m.ChatID())
		rec := quoteRecord{
			ID:          newID,
			ChatID:      m.ChatID(),
			UserID:      quotedID,
			UserName:    quotedName,
			UserHandle:  handle,
			Text:        text,
			SavedBy:     m.SenderID(),
			SavedByName: savedByName,
			Timestamp:   time.Now().Unix(),
		}
		raw, jerr := json.Marshal(&rec)
		if jerr != nil {
			return jerr
		}
		return b.Put(quotesChatKey(m.ChatID(), newID), raw)
	})
	return newID, werr
}

func QuoteImageHandler(m *tg.NewMessage) error {
	flags := quoteParseFlags(m.Args())
	target, err := quoteResolveTarget(m, flags)
	if err != nil || target == nil {
		m.Reply("<b>Usage:</b> reply to a message with <code>/q</code>.\nFlags: <code>r</code> include reply, <code>N</code> stack N messages, <code>p</code> image mode, <code>hd</code>, <code>q</code> blockquote style, <code>brand=apple|google|twitter</code>, <code>scale=1-20</code>, color name or hex.")
		return nil
	}
	return quoteRenderCore(m, target, flags)
}

func QuoteHDImageHandler(m *tg.NewMessage) error {
	flags := quoteParseFlags(m.Args())
	flags.HD = true
	target, err := quoteResolveTarget(m, flags)
	if err != nil || target == nil {
		m.Reply("<b>Usage:</b> reply to a message with <code>/qhd</code>.")
		return nil
	}
	return quoteRenderCore(m, target, flags)
}

func quoteResolveTarget(m *tg.NewMessage, _ quoteFlags) (*tg.NewMessage, error) {
	if !m.IsReply() {
		return nil, fmt.Errorf("no reply")
	}
	target, err := m.GetReplyMessage()
	if err != nil || target == nil {
		return nil, fmt.Errorf("could not read reply")
	}
	return target, nil
}

func QuoteVoteCallback(m *tg.CallbackQuery) error {
	data := string(m.Data)
	parts := strings.Split(data, ":")
	if len(parts) != 3 {
		m.Answer("bad vote", &tg.CallbackOptions{Alert: false})
		return nil
	}
	quoteID, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		m.Answer("bad vote", &tg.CallbackOptions{Alert: false})
		return nil
	}
	direction := parts[2]
	if direction != "up" && direction != "down" {
		m.Answer("bad vote", &tg.CallbackOptions{Alert: false})
		return nil
	}
	chatID := m.ChatID
	if !quoteRateIsOn(chatID) {
		m.Answer("voting is disabled here", &tg.CallbackOptions{Alert: false})
		return nil
	}
	quoteVoteMu.Lock()
	defer quoteVoteMu.Unlock()
	rec := quoteVoteGet(chatID, quoteID)
	if rec == nil {
		m.Answer("quote not found", &tg.CallbackOptions{Alert: false})
		return nil
	}
	uid := m.SenderID
	if rec.Up == nil {
		rec.Up = map[int64]bool{}
	}
	if rec.Down == nil {
		rec.Down = map[int64]bool{}
	}
	toast := ""
	if direction == "up" {
		if rec.Up[uid] {
			delete(rec.Up, uid)
			toast = "removed 👍"
		} else {
			rec.Up[uid] = true
			delete(rec.Down, uid)
			toast = "👍"
		}
	} else {
		if rec.Down[uid] {
			delete(rec.Down, uid)
			toast = "removed 👎"
		} else {
			rec.Down[uid] = true
			delete(rec.Up, uid)
			toast = "👎"
		}
	}
	_ = quoteVoteSave(rec)
	kb := quoteVoteKeyboard(chatID, quoteID, len(rec.Up), len(rec.Down))
	// Raw edit: Client.EditMessage forces a " " caption, which stickers reject.
	if peer, perr := m.Client.ResolvePeer(chatID); perr == nil {
		_, _ = m.Client.MessagesEditMessage(&tg.MessagesEditMessageParams{Peer: peer, ID: rec.MessageID, ReplyMarkup: kb})
	}
	m.Answer(toast, &tg.CallbackOptions{Alert: false})
	return nil
}

func QuoteRateHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("<b>/qrate</b> works in groups only.")
		return nil
	}
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "") {
		m.Reply("<b>Admins only.</b>")
		return nil
	}
	arg := strings.ToLower(strings.TrimSpace(m.Args()))
	switch arg {
	case "on", "enable":
		if err := quoteRateSet(m.ChatID(), true); err != nil {
			m.Reply("<b>DB error.</b>")
			return nil
		}
		m.Reply("<b>Quote voting enabled.</b> New <code>/q</code> messages will get 👍/👎 buttons.")
	case "off", "disable":
		if err := quoteRateSet(m.ChatID(), false); err != nil {
			m.Reply("<b>DB error.</b>")
			return nil
		}
		m.Reply("<b>Quote voting disabled.</b>")
	default:
		state := "off"
		if quoteRateIsOn(m.ChatID()) {
			state = "on"
		}
		m.Reply(fmt.Sprintf("<b>Quote voting:</b> <code>%s</code>\n<i>Usage:</i> <code>/qrate on|off</code>", state))
	}
	return nil
}

func QuoteRandHandler(m *tg.NewMessage) error {
	all, err := quotesListByChat(m.ChatID())
	if err != nil || len(all) == 0 {
		m.Reply("<b>No quotes saved here yet.</b> Run <code>/q</code> on a message first.")
		return nil
	}
	rec := all[rand.IntN(len(all))]
	preview := rec.Text
	preview = quoteTrunc(preview, 300)
	m.Reply(fmt.Sprintf("<b>%s</b> once said <code>#%d</code>:\n\n<i>%s</i>",
		html.EscapeString(rec.UserName), rec.ID, html.EscapeString(preview)))
	return nil
}

func QuoteTopHandler(m *tg.NewMessage) error {
	n := 10
	if a := strings.TrimSpace(m.Args()); a != "" {
		if v, err := strconv.Atoi(a); err == nil && v > 0 && v <= 50 {
			n = v
		}
	}
	d, err := db.GetDB()
	if err != nil || d == nil {
		m.Reply("<b>DB error.</b>")
		return nil
	}
	type ranked struct {
		Rec   *quoteVoteRecord
		Score int
	}
	var out []ranked
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, uint64(m.ChatID()))
	_ = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket(quoteVotesBucket())
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rec quoteVoteRecord
			if jerr := json.Unmarshal(v, &rec); jerr != nil {
				continue
			}
			score := len(rec.Up) - len(rec.Down)
			if score == 0 && len(rec.Up)+len(rec.Down) == 0 {
				continue
			}
			out = append(out, ranked{&rec, score})
		}
		return nil
	})
	if len(out) == 0 {
		m.Reply("<b>No voted quotes yet.</b> Enable voting with <code>/qrate on</code>.")
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Rec.Timestamp > out[j].Rec.Timestamp
	})
	if len(out) > n {
		out = out[:n]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>Top Quotes</b> (top %d)\n━━━━━━━━━━━━━━━━\n\n", len(out))
	for i, r := range out {
		fmt.Fprintf(&sb, "<b>%d.</b> <code>#%d</code> <b>%s</b> — 👍 %d 👎 %d (score %+d)\n<i>%s</i>\n\n",
			i+1, r.Rec.QuoteID, html.EscapeString(r.Rec.QuotedName), len(r.Rec.Up), len(r.Rec.Down), r.Score, html.EscapeString(r.Rec.Preview))
	}
	m.Reply(sb.String())
	return nil
}

type quoteChatPack struct {
	OwnerID      int64  `json:"owner_id"`
	OwnerName    string `json:"owner_name"`
	ShortName    string `json:"short_name"`
	Title        string `json:"title"`
	PackNumber   int    `json:"pack_number"`
	StickerCount int    `json:"sticker_count"`
}

func quoteChatPackGet(chatID int64) *quoteChatPack {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return nil
	}
	var pack quoteChatPack
	found := false
	_ = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket(quotePacksBucket())
		if b == nil {
			return nil
		}
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, uint64(chatID))
		raw := b.Get(key)
		if raw == nil {
			return nil
		}
		if jerr := json.Unmarshal(raw, &pack); jerr == nil {
			found = true
		}
		return nil
	})
	if !found {
		return nil
	}
	return &pack
}

func quoteChatPackSave(chatID int64, pack *quoteChatPack) error {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return fmt.Errorf("db unavailable")
	}
	return d.Update(func(tx *mongostore.Tx) error {
		b, e := tx.CreateBucketIfNotExists(quotePacksBucket())
		if e != nil {
			return e
		}
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, uint64(chatID))
		raw, jerr := json.Marshal(pack)
		if jerr != nil {
			return jerr
		}
		return b.Put(key, raw)
	})
}

func QuoteStickerHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("<b>/qs</b> works in groups only.")
		return nil
	}
	flags := quoteParseFlags(m.Args())
	flags.ImageMode, flags.HD = false, false
	target, err := quoteResolveTarget(m, flags)
	if err != nil || target == nil {
		m.Reply("<b>Usage:</b> reply to a message with <code>/qs</code> to add it to this group's quote sticker pack.")
		return nil
	}
	if strings.TrimSpace(target.RawText()) == "" {
		m.Reply("<b>Nothing to quote.</b>")
		return nil
	}
	me := m.Client.Me()
	if me == nil || me.Username == "" {
		m.Reply("<b>Error:</b> bot has no username; cannot own sticker sets.")
		return nil
	}

	status, _ := m.Reply("<i>rendering + adding to pack...</i>")

	data, _, rerr := quoteRequestImage(quoteBuildRequest(m, target, flags), false)
	if rerr != nil {
		quoteStatus(m, status, "<b>Quote failed:</b> "+html.EscapeString(rerr.Error()))
		return nil
	}
	ts := time.Now().UnixNano()
	rawPath := filepath.Join(os.TempDir(), fmt.Sprintf("qs_%d_raw", ts))
	outPath := filepath.Join(os.TempDir(), fmt.Sprintf("qs_%d.webp", ts))
	defer os.Remove(rawPath)
	defer os.Remove(outPath)
	if werr := os.WriteFile(rawPath, data, 0o644); werr != nil {
		quoteStatus(m, status, "<b>Quote failed:</b> "+html.EscapeString(werr.Error()))
		return nil
	}
	// Sticker sets require 512px on the longest side and at most 512 KiB.
	if eerr := kangEncodeImage(rawPath, outPath); eerr != nil {
		quoteStatus(m, status, "<b>Quote failed:</b> "+html.EscapeString(eerr.Error()))
		return nil
	}

	media, gerr := modules.TransferSendableMedia(m.Client, outPath, &tg.MediaMetadata{Inline: true})
	if gerr != nil {
		quoteStatus(m, status, "<b>Upload failed:</b> "+html.EscapeString(gerr.Error()))
		return nil
	}
	inMedia, ok := media.(*tg.InputMediaDocument)
	if !ok {
		quoteStatus(m, status, "<b>Upload failed:</b> unexpected media type from Telegram.")
		return nil
	}
	item := &tg.InputStickerSetItem{Document: inMedia.ID, Emoji: "💬"}

	pack := quoteChatPackGet(m.ChatID())
	if pack != nil && pack.StickerCount < MaxStickersPerPack {
		_, addErr := m.Client.StickersAddStickerToSet(&tg.InputStickerSetShortName{ShortName: pack.ShortName}, item)
		if addErr == nil {
			pack.StickerCount++
			_ = quoteChatPackSave(m.ChatID(), pack)
			quoteStatus(m, status, fmt.Sprintf(
				"<b>Added to this chat's quote pack.</b>\nPack: <a href=\"https://t.me/addstickers/%s\">%s</a>\nStickers: %d/%d",
				pack.ShortName, html.EscapeString(pack.Title), pack.StickerCount, MaxStickersPerPack,
			))
			return nil
		}
		// Full or deleted packs roll over to a new one; anything else is reported.
		if !tg.MatchError(addErr, "STICKERPACK_STICKERS_TOO_MUCH") && !tg.MatchError(addErr, "STICKERSET_INVALID") {
			quoteStatus(m, status, stickerFriendlyError(m, addErr))
			return nil
		}
	}

	chatIDAbs := m.ChatID()
	if chatIDAbs < 0 {
		chatIDAbs = -chatIDAbs
	}
	title := ""
	if chat, cerr := m.Client.GetChat(m.ChatID()); cerr == nil && chat != nil {
		title = chat.Title
	} else if ch, cerr := m.Client.GetChannel(m.ChatID()); cerr == nil && ch != nil {
		title = ch.Title
	}
	if title == "" {
		title = fmt.Sprintf("Chat %d", m.ChatID())
	}
	ownerID, ownerName := m.SenderID(), quoteSenderName(m)
	packNumber := 1
	if pack != nil {
		ownerID, ownerName = pack.OwnerID, pack.OwnerName
		packNumber = pack.PackNumber + 1
	}
	if ownerID == 0 {
		quoteStatus(m, status, "<b>Error:</b> send /qs as yourself (not anonymously) so the pack has an owner.")
		return nil
	}
	ownerHash := quoteResolveAccessHash(m, ownerID)

	var shortName, fullTitle string
	var createErr error
	for range 10 {
		shortName = fmt.Sprintf("xquotes_%d_%d_by_%s", chatIDAbs, packNumber, me.Username)
		fullTitle = quoteClip(fmt.Sprintf("%s — Quotes #%d", title, packNumber), 64)
		_, createErr = m.Client.StickersCreateStickerSet(&tg.StickersCreateStickerSetParams{
			UserID:    &tg.InputUserObj{UserID: ownerID, AccessHash: ownerHash},
			Title:     fullTitle,
			ShortName: shortName,
			Stickers:  []*tg.InputStickerSetItem{item},
		})
		if createErr == nil || !tg.MatchError(createErr, "SHORT_NAME_OCCUPIED") {
			break
		}
		packNumber++
	}
	if createErr != nil {
		quoteStatus(m, status, stickerFriendlyError(m, createErr))
		return nil
	}
	newPack := &quoteChatPack{
		OwnerID:      ownerID,
		OwnerName:    ownerName,
		ShortName:    shortName,
		Title:        fullTitle,
		PackNumber:   packNumber,
		StickerCount: 1,
	}
	if err := quoteChatPackSave(m.ChatID(), newPack); err != nil {
		quoteStatus(m, status, "Pack created on Telegram but DB save failed: "+html.EscapeString(err.Error()))
		return nil
	}
	quoteStatus(m, status, fmt.Sprintf(
		"<b>New quote pack created for this chat.</b>\nPack: <a href=\"https://t.me/addstickers/%s\">%s</a>\nStickers: 1/%d",
		shortName, html.EscapeString(fullTitle), MaxStickersPerPack,
	))
	return nil
}

func quoteResolveAccessHash(m *tg.NewMessage, userID int64) int64 {
	if m.Sender != nil && m.Sender.ID == userID {
		return m.Sender.AccessHash
	}
	if u, err := m.Client.GetUser(userID); err == nil && u != nil {
		return u.AccessHash
	}
	return 0
}

func quotesEnsureBucket() error {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return fmt.Errorf("db unavailable")
	}
	return d.Update(func(tx *mongostore.Tx) error {
		_, e := tx.CreateBucketIfNotExists(quotesBucket)
		return e
	})
}

func quotesChatKey(chatID int64, id uint64) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], uint64(chatID))
	binary.BigEndian.PutUint64(b[8:16], id)
	return b
}

func quotesNextID(tx *mongostore.Tx, chatID int64) uint64 {
	b := tx.Bucket(quotesBucket)
	if b == nil {
		return 1
	}
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, uint64(chatID))
	c := b.Cursor()
	var maxID uint64
	for k, _ := c.Seek(prefix); len(k) >= 16; k, _ = c.Next() {
		if !bytes.HasPrefix(k, prefix) {
			break
		}
		id := binary.BigEndian.Uint64(k[8:16])
		if id > maxID {
			maxID = id
		}
	}
	return maxID + 1
}

func quotesListByChat(chatID int64) ([]quoteRecord, error) {
	if err := quotesEnsureBucket(); err != nil {
		return nil, err
	}
	d, err := db.GetDB()
	if err != nil || d == nil {
		return nil, fmt.Errorf("db unavailable")
	}
	var out []quoteRecord
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, uint64(chatID))
	err = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket(quotesBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rec quoteRecord
			if jerr := json.Unmarshal(v, &rec); jerr == nil {
				out = append(out, rec)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

func QuoteSaveHandler(m *tg.NewMessage) error {
	if !m.IsReply() {
		m.Reply("<b>Usage:</b> reply to a message with <code>/qsave</code> to save it.")
		return nil
	}
	reply, err := m.GetReplyMessage()
	if err != nil || reply == nil {
		m.Reply("<b>Could not fetch the replied message.</b>")
		return nil
	}
	text := strings.TrimSpace(reply.RawText())
	if text == "" {
		m.Reply("<b>Nothing to save.</b> The message has no text.")
		return nil
	}
	text = quoteClip(text, 4000)

	var userID int64
	name := "User"
	handle := ""
	if reply.SenderID() != 0 {
		userID = reply.SenderID()
		u, uerr := m.Client.GetUser(userID)
		if uerr == nil && u != nil {
			name = strings.TrimSpace(u.FirstName + " " + u.LastName)
			if name == "" {
				name = "User"
			}
			handle = u.Username
		}
	}

	savedByName := "User"
	if m.Sender != nil {
		savedByName = strings.TrimSpace(m.Sender.FirstName + " " + m.Sender.LastName)
		if savedByName == "" {
			savedByName = "User"
		}
	}

	if err := quotesEnsureBucket(); err != nil {
		m.Reply("<b>DB error.</b>")
		return nil
	}
	d, derr := db.GetDB()
	if derr != nil || d == nil {
		m.Reply("<b>DB error.</b>")
		return nil
	}

	var newID uint64
	werr := d.Update(func(tx *mongostore.Tx) error {
		b, e := tx.CreateBucketIfNotExists(quotesBucket)
		if e != nil {
			return e
		}
		newID = quotesNextID(tx, m.ChatID())
		rec := quoteRecord{
			ID:          newID,
			ChatID:      m.ChatID(),
			UserID:      userID,
			UserName:    name,
			UserHandle:  handle,
			Text:        text,
			SavedBy:     m.SenderID(),
			SavedByName: savedByName,
			Timestamp:   time.Now().Unix(),
		}
		raw, jerr := json.Marshal(&rec)
		if jerr != nil {
			return jerr
		}
		return b.Put(quotesChatKey(m.ChatID(), newID), raw)
	})
	if werr != nil {
		m.Reply("<b>Failed to save quote.</b>")
		return nil
	}

	preview := text
	preview = quoteTrunc(preview, 120)
	m.Reply(fmt.Sprintf("<b>Quote saved.</b> <code>#%d</code>\n\n<b>%s</b>: <i>%s</i>",
		newID, html.EscapeString(name), html.EscapeString(preview)))
	return nil
}

func QuotesListHandler(m *tg.NewMessage) error {
	page := 1
	if a := strings.TrimSpace(m.Args()); a != "" {
		if n, err := strconv.Atoi(a); err == nil && n > 0 {
			page = n
		}
	}
	all, err := quotesListByChat(m.ChatID())
	if err != nil || len(all) == 0 {
		m.Reply("<b>No quotes saved here yet.</b> Reply to a message with <code>/qsave</code>.")
		return nil
	}
	perPage := 10
	totalPages := (len(all) + perPage - 1) / perPage
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * perPage
	end := min(start+perPage, len(all))

	var resp strings.Builder
	fmt.Fprintf(&resp, "<b>Saved Quotes</b> (page %d/%d)\n", page, totalPages)
	resp.WriteString("━━━━━━━━━━━━━━━━\n\n")
	for _, rec := range all[start:end] {
		preview := rec.Text
		preview = quoteTrunc(preview, 90)
		fmt.Fprintf(&resp, "<code>#%d</code> <b>%s</b>\n<i>%s</i>\n\n",
			rec.ID,
			html.EscapeString(rec.UserName),
			html.EscapeString(preview))
	}
	fmt.Fprintf(&resp, "━━━━━━━━━━━━━━━━\n<b>Total:</b> %d quotes\n", len(all))
	if totalPages > 1 {
		fmt.Fprintf(&resp, "<i>Use</i> <code>/quotes %d</code> <i>for next page</i>", page+1)
	}
	m.Reply(resp.String())
	return nil
}

func QuoteDeleteHandler(m *tg.NewMessage) error {
	if !m.IsPrivate() {
		if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "change_info") {
			m.Reply("<b>Permission denied.</b> Admins only.")
			return nil
		}
	}
	arg := strings.TrimSpace(m.Args())
	arg = strings.TrimPrefix(arg, "#")
	if arg == "" {
		m.Reply("<b>Usage:</b> <code>/delq &lt;id&gt;</code>")
		return nil
	}
	id, err := strconv.ParseUint(arg, 10, 64)
	if err != nil || id == 0 {
		m.Reply("<b>Invalid id.</b>")
		return nil
	}
	if err := quotesEnsureBucket(); err != nil {
		m.Reply("<b>DB error.</b>")
		return nil
	}
	d, derr := db.GetDB()
	if derr != nil || d == nil {
		m.Reply("<b>DB error.</b>")
		return nil
	}
	found := false
	_ = d.Update(func(tx *mongostore.Tx) error {
		b := tx.Bucket(quotesBucket)
		if b == nil {
			return nil
		}
		key := quotesChatKey(m.ChatID(), id)
		if b.Get(key) == nil {
			return nil
		}
		found = true
		return b.Delete(key)
	})
	if !found {
		m.Reply(fmt.Sprintf("<b>Quote not found:</b> <code>#%d</code>", id))
		return nil
	}
	m.Reply(fmt.Sprintf("<b>Quote deleted:</b> <code>#%d</code>", id))
	return nil
}

func QuotesSearchHandler(m *tg.NewMessage) error {
	q := strings.ToLower(strings.TrimSpace(m.Args()))
	if q == "" {
		m.Reply("<b>Usage:</b> <code>/qsearch &lt;keyword&gt;</code>")
		return nil
	}
	all, err := quotesListByChat(m.ChatID())
	if err != nil || len(all) == 0 {
		m.Reply("<b>No quotes to search.</b>")
		return nil
	}
	var matches []quoteRecord
	for _, rec := range all {
		if strings.Contains(strings.ToLower(rec.Text), q) ||
			strings.Contains(strings.ToLower(rec.UserName), q) ||
			strings.Contains(strings.ToLower(rec.UserHandle), q) {
			matches = append(matches, rec)
		}
	}
	if len(matches) == 0 {
		m.Reply(fmt.Sprintf("<b>No quotes match:</b> <code>%s</code>", html.EscapeString(q)))
		return nil
	}
	var resp strings.Builder
	fmt.Fprintf(&resp, "<b>Quote Search:</b> <code>%s</code>\n", html.EscapeString(q))
	resp.WriteString("━━━━━━━━━━━━━━━━\n\n")
	limit := 15
	for i, rec := range matches {
		if i >= limit {
			fmt.Fprintf(&resp, "\n<i>...and %d more</i>", len(matches)-limit)
			break
		}
		preview := rec.Text
		preview = quoteTrunc(preview, 100)
		fmt.Fprintf(&resp, "<code>#%d</code> <b>%s</b>\n<i>%s</i>\n\n",
			rec.ID, html.EscapeString(rec.UserName), html.EscapeString(preview))
	}
	fmt.Fprintf(&resp, "━━━━━━━━━━━━━━━━\n<b>Matches:</b> %d", len(matches))
	m.Reply(resp.String())
	return nil
}

func registerQuotesHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:q", QuoteImageHandler)
	modules.OnCommand(c, "cmd:qhd", QuoteHDImageHandler)
	modules.OnCommand(c, "cmd:qsave", QuoteSaveHandler)
	modules.OnCommand(c, "cmd:quotes", QuotesListHandler)
	modules.OnCommand(c, "cmd:delq", QuoteDeleteHandler)
	modules.OnCommand(c, "cmd:qsearch", QuotesSearchHandler)
	modules.OnCommand(c, "cmd:qrate", QuoteRateHandler)
	modules.OnCommand(c, "cmd:qrand", QuoteRandHandler)
	modules.OnCommand(c, "cmd:qtop", QuoteTopHandler)
	modules.OnCommand(c, "cmd:qs", QuoteStickerHandler)
	c.On("callback:qvote:", QuoteVoteCallback)
}

func init() {
	modules.QueueHandlerRegistration(registerQuotesHandlers)

	modules.Mods.AddModule("Quotes", `<b>Quotes Module</b>

Turn messages into Telegram-style quote stickers and keep a per-chat quote book.

<b>Render:</b>
 - /q — reply to a message to render it as a quote sticker (also saves it)
 - /qhd — same, as a high-resolution PNG
 - /qs — add the quote to this group's shared sticker pack (groups only)

<b>/q flags</b> (any order, e.g. <code>/q r 3 red</code>):
 - <code>r</code> — include the message it replies to
 - <code>2</code>-<code>10</code> — stack that many recent messages
 - <code>p</code> — image mode (PNG instead of sticker)
 - <code>hd</code> — high resolution, <code>scale=1-10</code> — custom scale
 - <code>q</code> — blockquote style
 - <code>brand=apple|google|twitter</code> — emoji style
 - any other word or <code>#hex</code> — background colour

<b>Quote book:</b>
 - /qsave — reply to save a message without rendering
 - /quotes [page] — list saved quotes
 - /qsearch &lt;keyword&gt; — search by text or author
 - /qrand — a random saved quote
 - /delq &lt;id&gt; — delete a quote (admins in groups)

<b>Voting:</b>
 - /qrate on|off — add 👍/👎 buttons to new /q stickers (admins)
 - /qtop [n] — top voted quotes (default 10, max 50)

<i>Note:</i> /qs needs the person who creates the pack to have started the bot in DM.`)
}
