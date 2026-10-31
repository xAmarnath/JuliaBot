package extras

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"main/modules/db"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
	modules "main/modules"
)

const snipeBucket = "snipe_cfg"
const snipeRingSize = 20
const snipeMsgCacheMax = 500
const snipeCacheTTL = 12 * time.Hour

type snipedMsg struct {
	MessageID  int32
	ChatID     int64
	SenderID   int64
	SenderName string
	Text       string
	FileID     string
	IsSticker  bool
	OldText    string
	NewText    string
	IsEdit     bool
	Channel    bool
	Time       int64
}

type snipeCfg struct {
	Enabled bool `json:"enabled"`
}

var (
	snipeStore      = make(map[int64][]*snipedMsg)
	snipeEditStore  = make(map[int64][]*snipedMsg)
	snipeMu         sync.RWMutex
	snipeCache      = make(map[int64]*snipeCfg)
	snipeCacheMu    sync.RWMutex
	snipeMsgCache   = make(map[int64]map[int32]*snipedMsg)
	snipeMsgCacheMu sync.RWMutex
)

func snipeKey(chatID int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(chatID))
	return b
}

func defaultSnipeCfg() *snipeCfg {
	return &snipeCfg{Enabled: true}
}

func loadSnipeCfg(chatID int64) *snipeCfg {
	snipeCacheMu.RLock()
	if v, ok := snipeCache[chatID]; ok {
		cp := *v
		snipeCacheMu.RUnlock()
		return &cp
	}
	snipeCacheMu.RUnlock()

	cfg := defaultSnipeCfg()
	d, err := db.GetDB()
	if err != nil || d == nil {
		return cfg
	}
	_ = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(snipeBucket))
		if b == nil {
			return nil
		}
		raw := b.Get(snipeKey(chatID))
		if len(raw) == 0 {
			return nil
		}
		_ = json.Unmarshal(raw, cfg)
		return nil
	})

	snipeCacheMu.Lock()
	cp := *cfg
	snipeCache[chatID] = &cp
	snipeCacheMu.Unlock()
	return cfg
}

func saveSnipeCfg(chatID int64, cfg *snipeCfg) error {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return fmt.Errorf("db unavailable")
	}
	err = d.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(snipeBucket))
		if err != nil {
			return err
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return b.Put(snipeKey(chatID), raw)
	})
	if err != nil {
		return err
	}
	snipeCacheMu.Lock()
	cp := *cfg
	snipeCache[chatID] = &cp
	snipeCacheMu.Unlock()
	return nil
}

func truncRunes(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func snipeAuthorName(m *tg.NewMessage) string {
	if m.Sender == nil {
		return "Unknown"
	}
	name := strings.TrimSpace(m.Sender.FirstName + " " + m.Sender.LastName)
	if name == "" {
		name = m.Sender.Username
	}
	if name == "" {
		name = strconv.FormatInt(m.Sender.ID, 10)
	}
	return name
}

func snipeCacheMessage(m *tg.NewMessage) {
	if m == nil || m.Message == nil {
		return
	}
	chatID := m.ChatID()
	if chatID == 0 {
		return
	}
	if !loadSnipeCfg(chatID).Enabled {
		return
	}

	entry := &snipedMsg{
		MessageID:  m.ID,
		ChatID:     chatID,
		SenderID:   m.SenderID(),
		SenderName: snipeAuthorName(m),
		Text:       m.Text(),
		Time:       time.Now().Unix(),
	}
	if _, ok := m.Message.PeerID.(*tg.PeerChannel); ok {
		entry.Channel = true
	}

	if m.IsMedia() && m.File != nil {
		entry.FileID = m.File.FileID
		if m.Sticker() != nil {
			entry.IsSticker = true
		}
	}

	snipeMsgCacheMu.Lock()
	cm, ok := snipeMsgCache[chatID]
	if !ok {
		cm = make(map[int32]*snipedMsg)
		snipeMsgCache[chatID] = cm
	}
	cm[m.ID] = entry
	// Evict in batches so the O(n) scan runs once per ~100 messages, not on every one.
	if len(cm) > snipeMsgCacheMax+100 {
		snipeEvictOldest(cm, snipeMsgCacheMax)
	}
	snipeMsgCacheMu.Unlock()
}

// snipeEvictOldest keeps the `keep` highest message IDs (IDs grow monotonically per chat).
func snipeEvictOldest(cm map[int32]*snipedMsg, keep int) {
	if len(cm) <= keep {
		return
	}
	ids := make([]int32, 0, len(cm))
	for id := range cm {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })
	for _, id := range ids[keep:] {
		delete(cm, id)
	}
}

func snipeCacheGet(chatID int64, msgID int32) *snipedMsg {
	snipeMsgCacheMu.RLock()
	defer snipeMsgCacheMu.RUnlock()
	if m, ok := snipeMsgCache[chatID]; ok {
		if e, ok := m[msgID]; ok {
			return e
		}
	}
	return nil
}

func snipeCacheRemove(chatID int64, msgID int32) {
	snipeMsgCacheMu.Lock()
	defer snipeMsgCacheMu.Unlock()
	if m, ok := snipeMsgCache[chatID]; ok {
		delete(m, msgID)
	}
}

func snipePush(chatID int64, entry *snipedMsg) {
	snipeMu.Lock()
	defer snipeMu.Unlock()
	if entry.IsEdit {
		snipeEditStore[chatID] = append([]*snipedMsg{entry}, snipeEditStore[chatID]...)
		if len(snipeEditStore[chatID]) > snipeRingSize {
			snipeEditStore[chatID] = snipeEditStore[chatID][:snipeRingSize]
		}
	} else {
		snipeStore[chatID] = append([]*snipedMsg{entry}, snipeStore[chatID]...)
		if len(snipeStore[chatID]) > snipeRingSize {
			snipeStore[chatID] = snipeStore[chatID][:snipeRingSize]
		}
	}
}

func snipeGetDeleted(chatID int64) []*snipedMsg {
	snipeMu.RLock()
	defer snipeMu.RUnlock()
	res := make([]*snipedMsg, len(snipeStore[chatID]))
	copy(res, snipeStore[chatID])
	return res
}

func snipeGetLastEdit(chatID int64) *snipedMsg {
	snipeMu.RLock()
	defer snipeMu.RUnlock()
	if len(snipeEditStore[chatID]) > 0 {
		return snipeEditStore[chatID][0]
	}
	return nil
}

func SnipeCacheHandler(m *tg.NewMessage) error {
	if m == nil || m.IsPrivate() {
		return nil
	}
	if m.SenderID() == 0 {
		return nil
	}
	snipeCacheMessage(m)
	return nil
}

func SnipeDeleteHandler(d *tg.DeleteMessage) error {
	if d == nil {
		return nil
	}

	// m.ChatID() keys the cache by the raw channel ID, which is what the update carries.
	chatID := d.ChannelID

	for _, msgID := range d.Messages {
		var entry *snipedMsg
		if chatID != 0 {
			entry = snipeCacheGet(chatID, msgID)
		} else {
			// Basic-group message IDs are account-global, so scanning non-channel chats is unambiguous.
			snipeMsgCacheMu.RLock()
			for _, m := range snipeMsgCache {
				if e, ok := m[msgID]; ok && !e.Channel {
					entry = e
					break
				}
			}
			snipeMsgCacheMu.RUnlock()
		}
		if entry == nil {
			continue
		}
		if !loadSnipeCfg(entry.ChatID).Enabled {
			snipeCacheRemove(entry.ChatID, msgID)
			continue
		}
		snipePush(entry.ChatID, entry)
		snipeCacheRemove(entry.ChatID, msgID)
	}
	return nil
}

func SnipeEditHandler(m *tg.NewMessage) error {
	if m == nil || m.IsPrivate() {
		return nil
	}
	if m.SenderID() == 0 {
		return nil
	}
	chatID := m.ChatID()
	if !loadSnipeCfg(chatID).Enabled {
		snipeCacheMessage(m)
		return nil
	}

	old := snipeCacheGet(chatID, m.ID)
	newText := m.Text()
	if old != nil && old.Text != newText {
		entry := &snipedMsg{
			MessageID:  m.ID,
			ChatID:     chatID,
			SenderID:   m.SenderID(),
			SenderName: snipeAuthorName(m),
			OldText:    old.Text,
			NewText:    newText,
			IsEdit:     true,
			Time:       time.Now().Unix(),
		}
		snipePush(chatID, entry)
	}

	snipeCacheMessage(m)
	return nil
}

func formatSnipeTime(ts int64) string {
	d := time.Since(time.Unix(ts, 0))
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func sendSnipedEntry(m *tg.NewMessage, entry *snipedMsg) {
	header := fmt.Sprintf("<b>Sniped from %s</b> <i>(%s)</i>", html.EscapeString(entry.SenderName), formatSnipeTime(entry.Time))

	if entry.FileID != "" {
		caption := header
		if entry.Text != "" {
			caption += "\n\n" + html.EscapeString(truncRunes(entry.Text, 900))
		}
		media, err := tg.ResolveBotFileID(entry.FileID)
		if err == nil {
			if entry.IsSticker {
				modules.TransferReplyMedia(m, media)
				m.Respond(caption)
			} else {
				modules.TransferReplyMedia(m, media, &tg.MediaOptions{Caption: caption})
			}
			return
		}
	}

	body := header
	if entry.Text != "" {
		body += "\n\n" + html.EscapeString(truncRunes(entry.Text, 3800))
	} else {
		body += "\n\n<i>[no text]</i>"
	}
	m.Reply(body)
}

func SnipeHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("<b>Snipe works in groups only.</b>")
		return nil
	}

	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "") {
		m.Reply("Admins only.")
		return nil
	}

	arg := strings.TrimSpace(m.Args())
	argLower := strings.ToLower(arg)
	switch argLower {
	case "on", "off", "enable", "disable", "yes", "no":
		return SnipeToggleHandler(m)
	}

	if !loadSnipeCfg(m.ChatID()).Enabled {
		m.Reply("<b>Snipe is disabled in this chat.</b>")
		return nil
	}

	n := 1
	if arg != "" {
		v, err := strconv.Atoi(arg)
		if err != nil || v < 1 {
			m.Reply("<b>Usage:</b> <code>/snipe [N]</code> or <code>/snipe on|off</code>")
			return nil
		}
		n = v
	}

	deleted := snipeGetDeleted(m.ChatID())
	if len(deleted) == 0 {
		m.Reply("<b>Nothing to snipe.</b>")
		return nil
	}
	if n > len(deleted) {
		m.Reply(fmt.Sprintf("<b>Only %d deleted message(s) available.</b>", len(deleted)))
		return nil
	}

	sendSnipedEntry(m, deleted[n-1])
	return nil
}

func ESnipeHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("<b>Snipe works in groups only.</b>")
		return nil
	}
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "") {
		m.Reply("Admins only.")
		return nil
	}
	if !loadSnipeCfg(m.ChatID()).Enabled {
		m.Reply("<b>Snipe is disabled in this chat.</b>")
		return nil
	}

	entry := snipeGetLastEdit(m.ChatID())
	if entry == nil {
		m.Reply("<b>No edits sniped.</b>")
		return nil
	}

	body := fmt.Sprintf("<b>Edit by %s</b> <i>(%s)</i>\n\n<s>%s</s> → <b>%s</b>",
		html.EscapeString(entry.SenderName),
		formatSnipeTime(entry.Time),
		html.EscapeString(truncRunes(entry.OldText, 1800)),
		html.EscapeString(truncRunes(entry.NewText, 1800)),
	)
	m.Reply(body)
	return nil
}

func renderSnipesPage(entries []*snipedMsg, page int) (string, int, int) {
	const perPage = 10
	total := len(entries)
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * perPage
	end := start + perPage
	if end > total {
		end = total
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("<b>Sniped Messages</b> <i>(page %d/%d)</i>\n", page, totalPages))
	sb.WriteString("━━━━━━━━━━━━━━━━\n\n")

	if total == 0 {
		sb.WriteString("<i>Nothing to snipe.</i>")
		return sb.String(), page, totalPages
	}

	for i := start; i < end; i++ {
		entry := entries[i]
		preview := entry.Text
		if preview == "" {
			if entry.IsSticker {
				preview = "[sticker]"
			} else if entry.FileID != "" {
				preview = "[media]"
			} else {
				preview = "[no text]"
			}
		}
		preview = truncRunes(preview, 80)
		sb.WriteString(fmt.Sprintf("<b>%d.</b> <b>%s</b> <i>(%s)</i>\n  %s\n\n",
			i+1,
			html.EscapeString(entry.SenderName),
			formatSnipeTime(entry.Time),
			html.EscapeString(preview),
		))
	}

	return sb.String(), page, totalPages
}

func snipesKeyboard(page, totalPages int, userID int64) *tg.ReplyInlineMarkup {
	if totalPages <= 1 {
		return nil
	}
	b := tg.Button
	kb := tg.NewKeyboard()
	var row []tg.KeyboardInlineButton
	if page > 1 {
		row = append(row, b.Data("« Prev", fmt.Sprintf("snipes_%d_%d", page-1, userID)))
	}
	row = append(row, b.Data(fmt.Sprintf("%d/%d", page, totalPages), "snipes_noop"))
	if page < totalPages {
		row = append(row, b.Data("Next »", fmt.Sprintf("snipes_%d_%d", page+1, userID)))
	}
	kb.AddRow(row...)
	return kb.Build()
}

func SnipesHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("<b>Snipe works in groups only.</b>")
		return nil
	}
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "") {
		m.Reply("Admins only.")
		return nil
	}
	if !loadSnipeCfg(m.ChatID()).Enabled {
		m.Reply("<b>Snipe is disabled in this chat.</b>")
		return nil
	}

	page := 1
	arg := strings.TrimSpace(m.Args())
	if arg != "" {
		v, err := strconv.Atoi(arg)
		if err == nil && v >= 1 {
			page = v
		}
	}

	entries := snipeGetDeleted(m.ChatID())
	body, page, totalPages := renderSnipesPage(entries, page)

	opts := &tg.SendOptions{}
	if kb := snipesKeyboard(page, totalPages, m.SenderID()); kb != nil {
		opts.ReplyMarkup = kb
	}
	m.Reply(body, opts)
	return nil
}

func SnipesCallback(c *tg.CallbackQuery) error {
	data := c.DataString()
	if data == "snipes_noop" {
		c.Answer("")
		return nil
	}
	if !strings.HasPrefix(data, "snipes_") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(data, "snipes_"), "_")
	if len(parts) != 2 {
		return nil
	}
	page, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}
	ownerID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil
	}
	if c.SenderID != ownerID {
		c.Answer("This button is not for you.", &tg.CallbackOptions{Alert: true})
		return nil
	}

	entries := snipeGetDeleted(c.ChatID)
	body, page, totalPages := renderSnipesPage(entries, page)

	opts := &tg.SendOptions{}
	if kb := snipesKeyboard(page, totalPages, ownerID); kb != nil {
		opts.ReplyMarkup = kb
	}
	c.Edit(body, opts)
	c.Answer("")
	return nil
}

func SnipeToggleHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("<b>Snipe works in groups only.</b>")
		return nil
	}
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "change_info") {
		m.Reply("<b>Permission denied.</b> Admins only.")
		return nil
	}

	arg := strings.ToLower(strings.TrimSpace(m.Args()))
	cfg := loadSnipeCfg(m.ChatID())

	switch arg {
	case "on", "enable", "yes":
		cfg.Enabled = true
		if err := saveSnipeCfg(m.ChatID(), cfg); err != nil {
			m.Reply("<b>Failed to save.</b>")
			return nil
		}
		m.Reply("<b>Snipe enabled.</b>")
	case "off", "disable", "no":
		cfg.Enabled = false
		if err := saveSnipeCfg(m.ChatID(), cfg); err != nil {
			m.Reply("<b>Failed to save.</b>")
			return nil
		}
		snipeMu.Lock()
		delete(snipeStore, m.ChatID())
		delete(snipeEditStore, m.ChatID())
		snipeMu.Unlock()
		snipeMsgCacheMu.Lock()
		delete(snipeMsgCache, m.ChatID())
		snipeMsgCacheMu.Unlock()
		m.Reply("<b>Snipe disabled.</b> Buffer cleared.")
	default:
		state := "enabled"
		if !cfg.Enabled {
			state = "disabled"
		}
		m.Reply(fmt.Sprintf("<b>Snipe is %s.</b>\n<b>Usage:</b> <code>/snipe on|off</code>", state))
	}
	return nil
}

// snipeSweep drops cached messages older than snipeCacheTTL so idle chats don't pin memory forever.
func snipeSweep() {
	for range time.Tick(10 * time.Minute) {
		cutoff := time.Now().Add(-snipeCacheTTL).Unix()
		snipeMsgCacheMu.Lock()
		for cid, cm := range snipeMsgCache {
			for id, e := range cm {
				if e.Time < cutoff {
					delete(cm, id)
				}
			}
			if len(cm) == 0 {
				delete(snipeMsgCache, cid)
			}
		}
		snipeMsgCacheMu.Unlock()
	}
}

func registerSnipeHandlers() {
	c := modules.Client
	go snipeSweep()
	modules.OnCommand(c, "cmd:snipe", SnipeHandler)
	modules.OnCommand(c, "cmd:esnipe", ESnipeHandler)
	modules.OnCommand(c, "cmd:snipes", SnipesHandler)
	c.On("callback:snipes_", SnipesCallback)
	c.On(tg.OnNewMessage, SnipeCacheHandler)
	c.On(tg.OnEditMessage, SnipeEditHandler)
	c.On(tg.OnDeleteMessage, SnipeDeleteHandler)
}

func init() {
	modules.QueueHandlerRegistration(registerSnipeHandlers)

	modules.Mods.AddModule("Snipe", `<b>Snipe Module</b>

Recover deleted and edited messages in your chat.

<b>Commands:</b>
 • /snipe [N] - Recover Nth most recent deleted message (default 1)
 • /esnipe - Show the last edited message (old → new)
 • /snipes [page] - Paginated list of last 10 deleted messages
 • /snipe on|off - Enable/disable snipe in this chat (admins only)

<b>Example:</b> <code>/snipe 3</code>

<b>Buffer:</b> last 20 deleted/edited messages per chat, in memory only (lost on restart). Only messages seen in the last 12h can be recovered.
<b>Permission:</b> admins can view; admins with Change Info can toggle.`)

}
