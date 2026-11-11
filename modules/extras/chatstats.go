package extras

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"sync"

	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
	modules "main/modules"
	"main/modules/db"
)

const chatStatsBucket = "chatstats"

type chatStatsEntry struct {
	Total    int64            `json:"total"`
	Media    int64            `json:"media"`
	Stickers int64            `json:"stickers"`
	Links    int64            `json:"links"`
	Users    map[int64]int64  `json:"users"`
	Names    map[int64]string `json:"names"`
}

var (
	chatStatsCache   = make(map[int64]*chatStatsEntry)
	chatStatsDirty   = make(map[int64]bool)
	chatStatsCacheMu sync.Mutex
)

func chatStatsKey(chatID int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(chatID))
	return b
}

func chatStatsNewEntry() *chatStatsEntry {
	return &chatStatsEntry{
		Users: make(map[int64]int64),
		Names: make(map[int64]string),
	}
}

// chatStatsGet must be called without chatStatsCacheMu held; the disk load runs unlocked
// so a cold chat doesn't stall every other chat's tracker.
func chatStatsGet(chatID int64) *chatStatsEntry {
	chatStatsCacheMu.Lock()
	e, ok := chatStatsCache[chatID]
	chatStatsCacheMu.Unlock()
	if ok {
		return e
	}
	loaded := chatStatsLoadDisk(chatID)
	chatStatsCacheMu.Lock()
	defer chatStatsCacheMu.Unlock()
	if e, ok := chatStatsCache[chatID]; ok {
		return e
	}
	chatStatsCache[chatID] = loaded
	return loaded
}

func chatStatsLoadDisk(chatID int64) *chatStatsEntry {
	out := chatStatsNewEntry()
	d, err := db.GetDB()
	if err != nil || d == nil {
		return out
	}
	_ = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(chatStatsBucket))
		if b == nil {
			return nil
		}
		raw := b.Get(chatStatsKey(chatID))
		if len(raw) == 0 {
			return nil
		}
		_ = json.Unmarshal(raw, out)
		if out.Users == nil {
			out.Users = make(map[int64]int64)
		}
		if out.Names == nil {
			out.Names = make(map[int64]string)
		}
		return nil
	})
	return out
}

func chatStatsFlush() {
	chatStatsCacheMu.Lock()
	dirty := make(map[int64]*chatStatsEntry, len(chatStatsDirty))
	for cid := range chatStatsDirty {
		if e, ok := chatStatsCache[cid]; ok {
			cp := chatStatsNewEntry()
			cp.Total = e.Total
			cp.Media = e.Media
			cp.Stickers = e.Stickers
			cp.Links = e.Links
			for k, v := range e.Users {
				cp.Users[k] = v
			}
			for k, v := range e.Names {
				cp.Names[k] = v
			}
			dirty[cid] = cp
		}
	}
	chatStatsDirty = make(map[int64]bool)
	chatStatsCacheMu.Unlock()

	if len(dirty) == 0 {
		return
	}
	d, err := db.GetDB()
	if err == nil && d != nil {
		err = d.Update(func(tx *mongostore.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte(chatStatsBucket))
			if err != nil {
				return err
			}
			for cid, e := range dirty {
				raw, err := json.Marshal(e)
				if err != nil {
					continue
				}
				if err := b.Put(chatStatsKey(cid), raw); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if err != nil || d == nil {
		chatStatsCacheMu.Lock()
		for cid := range dirty {
			chatStatsDirty[cid] = true
		}
		chatStatsCacheMu.Unlock()
	}
}

func chatStatsHasURL(m *tg.NewMessage) bool {
	if m.Message != nil {
		for _, e := range m.Message.Entities {
			switch e.(type) {
			case *tg.MessageEntityURL, *tg.MessageEntityTextURL:
				return true
			}
		}
	}
	t := strings.ToLower(m.Text())
	if t == "" {
		return false
	}
	return strings.Contains(t, "http://") || strings.Contains(t, "https://") || strings.Contains(t, "t.me/") || strings.Contains(t, "www.")
}

func chatStatsSenderName(m *tg.NewMessage) string {
	if m.Sender == nil {
		return "User"
	}
	name := strings.TrimSpace(m.Sender.FirstName + " " + m.Sender.LastName)
	if name == "" {
		name = m.Sender.Username
	}
	if name == "" {
		name = fmt.Sprintf("User %d", m.Sender.ID)
	}
	return name
}

func ChatStatsTrackHandler(m *tg.NewMessage) error {
	if m == nil || m.Message == nil {
		return nil
	}
	if m.IsPrivate() {
		return nil
	}
	if m.IsService() {
		return nil
	}
	chatID := m.ChatID()
	senderID := m.SenderID()
	if chatID == 0 {
		return nil
	}

	isSticker := m.Sticker() != nil
	isMedia := false
	if !isSticker {
		switch m.Media().(type) {
		case nil, *tg.MessageMediaWebPage, *tg.MessageMediaEmpty:
		default:
			isMedia = true
		}
	}
	hasLink := chatStatsHasURL(m)
	name := chatStatsSenderName(m)

	e := chatStatsGet(chatID)
	chatStatsCacheMu.Lock()
	e.Total++
	if isMedia {
		e.Media++
	}
	if isSticker {
		e.Stickers++
	}
	if hasLink {
		e.Links++
	}
	if senderID != 0 {
		e.Users[senderID]++
		if name != "" {
			e.Names[senderID] = name
		}
	}
	chatStatsDirty[chatID] = true
	chatStatsCacheMu.Unlock()

	return nil
}

type chatStatsUser struct {
	ID    int64
	Count int64
	Name  string
}

// chatStatsTop snapshots the per-user counts under the lock and returns the top n.
func chatStatsTop(e *chatStatsEntry, n int) []chatStatsUser {
	chatStatsCacheMu.Lock()
	all := make([]chatStatsUser, 0, len(e.Users))
	for uid, c := range e.Users {
		all = append(all, chatStatsUser{ID: uid, Count: c, Name: e.Names[uid]})
	}
	chatStatsCacheMu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func chatStatsWriteTop(b *strings.Builder, users []chatStatsUser) {
	for i, u := range users {
		name := u.Name
		if name == "" {
			name = fmt.Sprintf("User %d", u.ID)
		}
		b.WriteString(fmt.Sprintf("%d. %s — <b>%d</b>\n", i+1, html.EscapeString(truncRunes(name, 40)), u.Count))
	}
}

func ChatStatsHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("Chat stats are only available in groups.")
		return nil
	}
	e := chatStatsGet(m.ChatID())

	chatStatsCacheMu.Lock()
	total := e.Total
	media := e.Media
	stickers := e.Stickers
	links := e.Links
	usersCount := len(e.Users)
	chatStatsCacheMu.Unlock()
	all := chatStatsTop(e, 20)

	chatTitle := "this chat"
	if m.Channel != nil && m.Channel.Title != "" {
		chatTitle = m.Channel.Title
	} else if m.Chat != nil && m.Chat.Title != "" {
		chatTitle = m.Chat.Title
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("<b>Chat Stats for %s</b>\n\n", html.EscapeString(chatTitle)))
	b.WriteString(fmt.Sprintf("Total messages: <b>%d</b>\n", total))
	b.WriteString(fmt.Sprintf("Media: <b>%d</b>\n", media))
	b.WriteString(fmt.Sprintf("Stickers: <b>%d</b>\n", stickers))
	b.WriteString(fmt.Sprintf("Links: <b>%d</b>\n", links))
	b.WriteString(fmt.Sprintf("Tracked users: <b>%d</b>\n", usersCount))

	if len(all) > 0 {
		b.WriteString("\n<b>Top users:</b>\n")
		chatStatsWriteTop(&b, all)
	}

	m.Reply(b.String())
	return nil
}

func TopUsersHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("Top users are only available in groups.")
		return nil
	}
	all := chatStatsTop(chatStatsGet(m.ChatID()), 10)
	if len(all) == 0 {
		m.Reply("No activity tracked yet in this chat.")
		return nil
	}

	var b strings.Builder
	b.WriteString("<b>Top 10 users by messages</b>\n\n")
	chatStatsWriteTop(&b, all)
	m.Reply(b.String())
	return nil
}

func registerChatStatsHandlers() {
	c := modules.Client
	c.On(tg.OnNewMessage, ChatStatsTrackHandler)
	modules.OnCommand(c, "cmd:chatstats", ChatStatsHandler)
	modules.OnCommand(c, "cmd:topusers", TopUsersHandler)
}

func init() {
	modules.QueueHandlerRegistration(registerChatStatsHandlers)

	modules.Mods.AddModule("ChatStats", `<b>Chat Stats</b>

Counts messages in groups the bot is in (from when the bot joined; saved every 30s).

<b>Commands:</b>
 • <code>/chatstats</code> - Totals (messages, media, stickers, links, users) and top 20 members
 • <code>/topusers</code> - Top 10 members by message count

<b>Example:</b> <code>/topusers</code>

<i>Groups only.</i>`)
}
