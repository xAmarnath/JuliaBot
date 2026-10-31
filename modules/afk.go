package modules

import (
	"encoding/json"
	"fmt"
	"html"
	"main/modules/db"
	"math/rand"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
)

type AFK struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Message  string `json:"message"`
	Media    string `json:"media"`
	Time     int64  `json:"time"`
}

const afkBucket = "afk"

var (
	afkList       = make(map[int64]AFK)
	afkByUsername = make(map[string]int64)
	afkMu         sync.RWMutex
	afkLoadOnce   sync.Once
	afkNotified   = make(map[[2]int64][]time.Time)
	afkNotifiedMu sync.Mutex
)

var randomAFKMessages = []string{
	"<b>%s</b> is AFK since <b>%s</b>.",
	"<b>%s</b> is AFK for <b>%s</b>.",
	"Mr. <b>%s</b> is AFK for <b>%s</b>.",
	"<b>%s</b> has been AFK since <b>%s</b>.",
	"<b>%s</b> stepped away and is AFK for <b>%s</b>.",
	"<b>%s</b> is currently AFK for <b>%s</b>.",
}

func afkLoad() {
	afkLoadOnce.Do(func() {
		database, err := db.GetDB()
		if err != nil || database == nil {
			return
		}
		_ = database.View(func(tx *mongostore.Tx) error {
			b := tx.Bucket([]byte(afkBucket))
			if b == nil {
				return nil
			}
			return b.ForEach(func(k, v []byte) error {
				id, err := strconv.ParseInt(string(k), 10, 64)
				if err != nil {
					return nil
				}
				var a AFK
				if json.Unmarshal(v, &a) == nil {
					afkMu.Lock()
					afkList[id] = a
					if a.Username != "" {
						afkByUsername[a.Username] = id
					}
					afkMu.Unlock()
				}
				return nil
			})
		})
	})
}

func afkPersist(id int64, a *AFK) {
	go func() {
		database, err := db.GetDB()
		if err != nil || database == nil {
			return
		}
		_ = database.Update(func(tx *mongostore.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte(afkBucket))
			if err != nil {
				return err
			}
			key := []byte(strconv.FormatInt(id, 10))
			if a == nil {
				return b.Delete(key)
			}
			data, err := json.Marshal(a)
			if err != nil {
				return err
			}
			return b.Put(key, data)
		})
	}()
}

func afkSet(id int64, a AFK) {
	afkMu.Lock()
	afkList[id] = a
	if a.Username != "" {
		afkByUsername[a.Username] = id
	}
	afkMu.Unlock()
	afkPersist(id, &a)
}

func afkGet(id int64) (AFK, bool) {
	afkMu.RLock()
	a, ok := afkList[id]
	afkMu.RUnlock()
	return a, ok
}

func afkClear(id int64) (AFK, bool) {
	afkMu.Lock()
	a, ok := afkList[id]
	if ok {
		delete(afkList, id)
		if a.Username != "" && afkByUsername[a.Username] == id {
			delete(afkByUsername, a.Username)
		}
	}
	afkMu.Unlock()
	if ok {
		afkPersist(id, nil)
	}
	return a, ok
}

func afkCount() int {
	afkMu.RLock()
	defer afkMu.RUnlock()
	return len(afkList)
}

func afkDuration(since int64) string {
	d := time.Since(time.Unix(since, 0))
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

func afkDisplayName(s *tg.UserObj) string {
	if s == nil {
		return "User"
	}
	name := strings.TrimSpace(strings.TrimSpace(s.FirstName + " " + s.LastName))
	if name == "" && s.Username != "" {
		name = s.Username
	}
	if name == "" {
		name = strconv.FormatInt(s.ID, 10)
	}
	return name
}

func mentionUsername(text string, offset, length int32) string {
	u := utf16.Encode([]rune(text))
	if offset < 0 || length <= 0 || int(offset+length) > len(u) {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(string(utf16.Decode(u[offset:offset+length])), "@"))
}

const (
	afkPerUserPerMinute = 20
	afkPerChatPerMinute = 30
)

func afkRecent(times []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(times) && now.Sub(times[i]) >= time.Minute {
		i++
	}
	return times[i:]
}

func afkShouldNotify(chatID, senderID int64) bool {
	afkNotifiedMu.Lock()
	defer afkNotifiedMu.Unlock()
	now := time.Now()
	userKey, chatKey := [2]int64{chatID, senderID}, [2]int64{chatID, 0}
	users, chats := afkRecent(afkNotified[userKey], now), afkRecent(afkNotified[chatKey], now)
	if len(users) >= afkPerUserPerMinute || len(chats) >= afkPerChatPerMinute {
		afkNotified[userKey], afkNotified[chatKey] = users, chats
		return false
	}
	afkNotified[userKey], afkNotified[chatKey] = append(users, now), append(chats, now)
	if len(afkNotified) > 8192 {
		for k, v := range afkNotified {
			if len(afkRecent(v, now)) == 0 {
				delete(afkNotified, k)
			}
		}
	}
	return true
}

func afkNotify(m *tg.NewMessage, afk AFK) {
	if !afkShouldNotify(m.ChatID(), m.SenderID()) {
		return
	}
	msg := fmt.Sprintf(randomAFKMessages[rand.Intn(len(randomAFKMessages))], html.EscapeString(afk.Name), afkDuration(afk.Time))
	if afk.Message != "" {
		msg += "\n<b>Reason:</b> " + html.EscapeString(afk.Message)
	}
	if afk.Media != "" {
		if media, err := tg.ResolveBotFileID(afk.Media); err == nil && media != nil {
			if IsSticker(media) {
				TransferReplyMedia(m, media)
				m.Respond(msg)
			} else {
				TransferReplyMedia(m, media, &tg.MediaOptions{Caption: msg})
			}
			return
		}
	}
	m.Reply(msg)
}

func isAFKCommand(text string) bool {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return false
	}
	cmd := strings.ToLower(fields[0])
	if i := strings.IndexByte(cmd, '@'); i > 0 {
		cmd = cmd[:i]
	}
	return cmd == "/afk" || cmd == "!afk" || cmd == ".afk" || cmd == "brb"
}

func AFKHandler(m *tg.NewMessage) error {
	if m.Sender == nil || m.Message == nil {
		return nil
	}
	afkLoad()

	if isAFKCommand(m.Text()) {
		media := ""
		if m.IsReply() {
			if r, err := m.GetReplyMessage(); err == nil && r != nil && r.IsMedia() && r.File != nil {
				media = r.File.FileID
			}
		}
		reason := m.Args()
		if strings.HasPrefix(strings.ToLower(m.Text()), "brb") {
			reason = strings.TrimSpace(m.Text()[3:])
		}
		afkSet(m.Sender.ID, AFK{
			Name:     afkDisplayName(m.Sender),
			Username: strings.ToLower(m.Sender.Username),
			Message:  reason,
			Media:    media,
			Time:     time.Now().Unix(),
		})
		m.Reply(fmt.Sprintf("<b>%s</b> is now AFK.", html.EscapeString(afkDisplayName(m.Sender))))
		return nil
	}

	if afkCount() == 0 {
		return nil
	}

	if afk, ok := afkClear(m.Sender.ID); ok {
		m.Reply(fmt.Sprintf("Welcome back <b>%s</b>! You were AFK for %s.", html.EscapeString(afk.Name), afkDuration(afk.Time)))
		return nil
	}

	targets := make(map[int64]bool)
	if m.IsReply() {
		if r, err := m.GetReplyMessage(); err == nil && r != nil {
			targets[r.SenderID()] = true
		}
	}
	text := m.Text()
	for _, entity := range m.Message.Entities {
		switch e := entity.(type) {
		case *tg.MessageEntityMentionName:
			targets[e.UserID] = true
		case *tg.MessageEntityMention:
			if name := mentionUsername(text, e.Offset, e.Length); name != "" {
				afkMu.RLock()
				id, ok := afkByUsername[name]
				afkMu.RUnlock()
				if ok {
					targets[id] = true
				}
			}
		}
	}
	for id := range targets {
		if id == 0 || id == m.Sender.ID {
			continue
		}
		if afk, ok := afkGet(id); ok {
			afkNotify(m, afk)
		}
	}
	return nil
}

func trimDecimal(s string) string {
	if strings.Contains(s, ".") {
		return strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

func IsSticker(m tg.MessageMedia) bool {
	switch m := m.(type) {
	case *tg.MessageMediaDocument:
		attrs := m.Document.(*tg.DocumentObj).Attributes
		for _, attr := range attrs {
			if _, ok := attr.(*tg.DocumentAttributeSticker); ok {
				return true
			}
		}
	}

	return false
}

func parseSed(text string) (find, replace, flags string, ok bool) {
	if len(text) < 4 || text[0] != 's' {
		return "", "", "", false
	}
	d := text[1]
	if d != '/' && d != '\\' && d != '|' && d != '#' {
		return "", "", "", false
	}
	rest := text[2:]

	take := func(s string) (segment, remainder string, found bool) {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) && s[i+1] == d {
				b.WriteByte(d)
				i++
				continue
			}
			if s[i] == d {
				return b.String(), s[i+1:], true
			}
			b.WriteByte(s[i])
		}
		return "", s, false
	}

	var found1, found2 bool
	find, rest, found1 = take(rest)
	if !found1 {
		return "", "", "", false
	}
	replace, rest, found2 = take(rest)
	if !found2 {
		replace = rest
		rest = ""
	}

	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case 'g', 'i':
			flags += string(rest[i])
		case ' ', '\t':
			i = len(rest)
		}
	}

	if find == "" {
		return "", "", "", false
	}
	return find, replace, flags, true
}

func expandSedBackrefs(repl string) string {
	var b strings.Builder
	for i := 0; i < len(repl); i++ {
		if repl[i] == '\\' && i+1 < len(repl) {
			c := repl[i+1]
			if c == '&' || c == '0' {
				b.WriteString("${0}")
				i++
				continue
			}
			if c >= '1' && c <= '9' {
				b.WriteString("${")
				b.WriteByte(c)
				b.WriteString("}")
				i++
				continue
			}
			if c == '\\' {
				b.WriteString(`\\`)
				i++
				continue
			}
		}
		if repl[i] == '&' {
			b.WriteString("${0}")
			continue
		}
		if repl[i] == '$' {
			b.WriteString(`$$`)
			continue
		}
		b.WriteByte(repl[i])
	}
	return b.String()
}

const sedMaxOutputLen = 4096

func SedHandler(m *tg.NewMessage) error {
	find, replace, flags, ok := parseSed(m.Text())
	if !ok {
		return nil
	}
	if !m.IsReply() {
		return nil
	}
	replyMsg, err := m.GetReplyMessage()
	if err != nil {
		return nil
	}
	if me := m.Client.Me(); me != nil && replyMsg.SenderID() == me.ID {
		return nil
	}
	originalText := replyMsg.Text()
	if originalText == "" {
		return nil
	}

	global := strings.ContainsRune(flags, 'g')
	insensitive := strings.ContainsRune(flags, 'i')

	pattern := find
	if insensitive {
		pattern = "(?i)" + pattern
	}

	var newText string
	if re, rerr := regexp.Compile(pattern); rerr == nil && re.MatchString(originalText) {
		goRepl := expandSedBackrefs(replace)
		if global {
			newText = re.ReplaceAllString(originalText, goRepl)
		} else {
			loc := re.FindStringIndex(originalText)
			if loc == nil {
				return nil
			}
			newText = originalText[:loc[0]] +
				re.ReplaceAllString(originalText[loc[0]:loc[1]], goRepl) +
				originalText[loc[1]:]
		}
	} else {
		haystack := originalText
		needle := find
		if insensitive {
			if lre, err := regexp.Compile("(?i)" + regexp.QuoteMeta(find)); err == nil {
				if !lre.MatchString(haystack) {
					return nil
				}
				if global {
					newText = lre.ReplaceAllString(haystack, replace)
				} else {
					newText = lre.ReplaceAllStringFunc(haystack, func(s string) string {
						return replace
					})
					if loc := lre.FindStringIndex(haystack); loc != nil {
						newText = haystack[:loc[0]] + replace + haystack[loc[1]:]
					}
				}
			} else {
				return nil
			}
		} else {
			if !strings.Contains(haystack, needle) {
				return nil
			}
			if global {
				newText = strings.ReplaceAll(haystack, needle, replace)
			} else {
				newText = strings.Replace(haystack, needle, replace, 1)
			}
		}
	}

	if newText == originalText {
		return nil
	}
	if len(newText) > sedMaxOutputLen {
		return nil
	}

	m.Respond(newText, &tg.SendOptions{ReplyID: replyMsg.ID})
	return nil
}

const lastSeenBucket = "last_seen"

type lastSeenEntry struct {
	UserID   int64  `json:"user_id"`
	ChatID   int64  `json:"chat_id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Time     int64  `json:"time"`
}

func humanRelative(t time.Time) string {
	d := time.Since(t)
	if d < 0 {
		d = -d
	}
	secs := int64(d.Seconds())
	if secs < 5 {
		return "just now"
	}
	if secs < 60 {
		return fmt.Sprintf("%d seconds ago", secs)
	}
	mins := secs / 60
	if mins < 60 {
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	}
	hours := mins / 60
	if hours < 24 {
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}
	days := hours / 24
	if days < 7 {
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
	weeks := days / 7
	if weeks < 4 {
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	}
	months := days / 30
	if months < 12 {
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	}
	years := days / 365
	if years == 1 {
		return "1 year ago"
	}
	return fmt.Sprintf("%d years ago", years)
}

func lastSeenKey(chatID, userID int64) []byte {
	return []byte(fmt.Sprintf("%d:%d", chatID, userID))
}

var (
	lastSeenMu      sync.Mutex
	lastSeenDirty   = make(map[string]*lastSeenEntry)
	lastSeenLatest  = make(map[int64]*lastSeenEntry)
	lastSeenFlusher sync.Once
)

const lastSeenFlushInterval = 20 * time.Second

func lastSeenFlushLoop() {
	t := time.NewTicker(lastSeenFlushInterval)
	defer t.Stop()
	for range t.C {
		flushLastSeen()
	}
}

func FlushLastSeen() { flushLastSeen() }

func flushLastSeen() {
	lastSeenMu.Lock()
	if len(lastSeenDirty) == 0 {
		lastSeenMu.Unlock()
		return
	}
	batch := lastSeenDirty
	lastSeenDirty = make(map[string]*lastSeenEntry, len(batch))
	lastSeenMu.Unlock()

	database, err := db.GetDB()
	if err != nil || database == nil {
		return
	}
	err = database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(lastSeenBucket))
		if err != nil {
			return err
		}
		for key, entry := range batch {
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			if err := b.Put([]byte(key), data); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		lastSeenMu.Lock()
		for k, v := range batch {
			if _, newer := lastSeenDirty[k]; !newer {
				lastSeenDirty[k] = v
			}
		}
		lastSeenMu.Unlock()
	}
}

func saveLastSeen(entry *lastSeenEntry) error {
	lastSeenFlusher.Do(func() { go lastSeenFlushLoop() })
	lastSeenMu.Lock()
	lastSeenDirty[string(lastSeenKey(entry.ChatID, entry.UserID))] = entry
	if cur := lastSeenLatest[entry.UserID]; cur == nil || entry.Time >= cur.Time {
		lastSeenLatest[entry.UserID] = entry
	}
	if len(lastSeenLatest) > 200000 {
		lastSeenLatest = make(map[int64]*lastSeenEntry)
	}
	lastSeenMu.Unlock()
	return nil
}

func loadLastSeen(chatID, userID int64) (*lastSeenEntry, error) {
	lastSeenMu.Lock()
	if e, ok := lastSeenDirty[string(lastSeenKey(chatID, userID))]; ok {
		lastSeenMu.Unlock()
		return e, nil
	}
	lastSeenMu.Unlock()
	database, err := db.GetDB()
	if err != nil || database == nil {
		return nil, fmt.Errorf("db error")
	}
	var entry *lastSeenEntry
	err = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(lastSeenBucket))
		if b == nil {
			return nil
		}
		v := b.Get(lastSeenKey(chatID, userID))
		if v == nil {
			return nil
		}
		var e lastSeenEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		entry = &e
		return nil
	})
	return entry, err
}

func loadAnyLastSeen(userID int64) (*lastSeenEntry, error) {
	lastSeenMu.Lock()
	recent := lastSeenLatest[userID]
	lastSeenMu.Unlock()
	if recent != nil {
		return recent, nil
	}
	database, err := db.GetDB()
	if err != nil || database == nil {
		return nil, fmt.Errorf("db error")
	}
	var best *lastSeenEntry
	suffix := ":" + strconv.FormatInt(userID, 10)
	err = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(lastSeenBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if !strings.HasSuffix(string(k), suffix) {
				return nil
			}
			var e lastSeenEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return nil
			}
			if best == nil || e.Time > best.Time {
				ec := e
				best = &ec
			}
			return nil
		})
	})
	return best, err
}

func LastSeenTracker(m *tg.NewMessage) error {
	if m.SenderID() == 0 || m.ChatID() == 0 {
		return nil
	}
	entry := &lastSeenEntry{
		UserID: m.SenderID(),
		ChatID: m.ChatID(),
		Time:   time.Now().Unix(),
	}
	if m.Sender != nil {
		entry.Name = m.Sender.FirstName
		entry.Username = m.Sender.Username
	}
	return saveLastSeen(entry)
}

func AfkUsersHandler(m *tg.NewMessage) error {
	chatID := m.ChatID()
	if chatID == 0 {
		m.Reply("<b>This command works in chats only.</b>")
		return nil
	}
	afkLoad()
	afkMu.RLock()
	snapshot := make(map[int64]AFK, len(afkList))
	for k, v := range afkList {
		snapshot[k] = v
	}
	afkMu.RUnlock()

	type row struct {
		id     int64
		name   string
		since  time.Time
		reason string
	}
	var rows []row
	for uid, a := range snapshot {
		entry, _ := loadLastSeen(chatID, uid)
		if entry == nil {
			continue
		}
		name := a.Name
		if name == "" {
			name = entry.Name
		}
		if name == "" {
			name = strconv.FormatInt(uid, 10)
		}
		rows = append(rows, row{id: uid, name: name, since: time.Unix(a.Time, 0), reason: a.Message})
	}

	if len(rows) == 0 {
		m.Reply("<b>No one in this chat is AFK right now.</b>")
		return nil
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].since.Before(rows[j].since)
	})

	var sb strings.Builder
	sb.WriteString("<b>AFK Users</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━\n")
	for _, r := range rows {
		mention := fmt.Sprintf("<a href='tg://user?id=%d'>%s</a>", r.id, html.EscapeString(r.name))
		sb.WriteString(fmt.Sprintf(" • %s — AFK for %s", mention, afkDuration(r.since.Unix())))
		if strings.TrimSpace(r.reason) != "" {
			sb.WriteString(fmt.Sprintf(" (<i>%s</i>)", html.EscapeString(r.reason)))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(fmt.Sprintf("\n<b>Total:</b> %d", len(rows)))
	m.Reply(sb.String())
	return nil
}

func LastSeenHandler(m *tg.NewMessage) error {
	chatID := m.ChatID()
	if chatID == 0 {
		m.Reply("<b>This command works in chats only.</b>")
		return nil
	}

	var targetID int64
	var targetName string

	if m.IsReply() {
		r, err := m.GetReplyMessage()
		if err == nil && r != nil {
			targetID = r.SenderID()
			if r.Sender != nil {
				targetName = r.Sender.FirstName
			}
		}
	} else if strings.TrimSpace(m.Args()) != "" {
		arg := strings.TrimSpace(strings.Split(m.Args(), " ")[0])
		argInt, convErr := strconv.ParseInt(arg, 10, 64)
		if convErr == nil {
			peer, err := m.Client.ResolvePeer(argInt)
			if err == nil {
				targetID = m.Client.GetPeerID(peer)
			}
		} else {
			peer, err := m.Client.ResolvePeer(arg)
			if err == nil {
				targetID = m.Client.GetPeerID(peer)
			}
		}
		if targetID != 0 {
			if u, _ := m.Client.GetUser(targetID); u != nil {
				targetName = u.FirstName
			}
		}
	} else {
		targetID = m.SenderID()
		if m.Sender != nil {
			targetName = m.Sender.FirstName
		}
	}

	if targetID == 0 {
		m.Reply("<b>Could not resolve user.</b>\nReply to a user or use <code>/lastseen @username</code>.")
		return nil
	}

	entry, _ := loadLastSeen(chatID, targetID)
	if entry == nil {
		fallback, _ := loadAnyLastSeen(targetID)
		if fallback == nil {
			name := targetName
			if name == "" {
				name = strconv.FormatInt(targetID, 10)
			}
			m.Reply(fmt.Sprintf("<b>%s</b> has not been seen in any tracked chat.", html.EscapeString(name)))
			return nil
		}
		name := fallback.Name
		if targetName != "" {
			name = targetName
		}
		if name == "" {
			name = strconv.FormatInt(targetID, 10)
		}
		mention := fmt.Sprintf("<a href='tg://user?id=%d'>%s</a>", targetID, html.EscapeString(name))
		m.Reply(fmt.Sprintf("%s was last seen %s (in another chat).", mention, humanRelative(time.Unix(fallback.Time, 0))))
		return nil
	}

	name := entry.Name
	if targetName != "" {
		name = targetName
	}
	if name == "" {
		name = strconv.FormatInt(targetID, 10)
	}
	mention := fmt.Sprintf("<a href='tg://user?id=%d'>%s</a>", targetID, html.EscapeString(name))

	extra := ""
	afkLoad()
	if afk, ok := afkGet(targetID); ok {
		extra = fmt.Sprintf("\n<b>Currently AFK</b> since %s.", humanRelative(time.Unix(afk.Time, 0)))
		if strings.TrimSpace(afk.Message) != "" {
			extra += fmt.Sprintf("\n<b>Reason:</b> %s", html.EscapeString(afk.Message))
		}
	}

	m.Reply(fmt.Sprintf("%s was last seen %s.%s", mention, humanRelative(time.Unix(entry.Time, 0)), extra))
	return nil
}

func registerAFKHandlers() {
	c := Client
	c.On(tg.OnNewMessage, AFKHandler)
	c.On(tg.OnNewMessage, SedHandler)
	c.On(tg.OnNewMessage, LastSeenTracker)
	OnCommand(c, "cmd:afkusers", AfkUsersHandler)
	OnCommand(c, "cmd:lastseen", LastSeenHandler)
	OnCommand(c, "cmd:seen", LastSeenHandler)
	Mods.AddModule("AFKStatus", `<b>AFK Status Module</b>
<b>Commands:</b>
 • /afkusers - List AFK users in this chat with last-seen times
 • /lastseen [reply | @user] - Show when a user was last seen
 • /seen - Alias for /lastseen
<i>Tracks last-seen timestamps per chat automatically.</i>`)
}

func init() {
	QueueHandlerRegistration(registerAFKHandlers)
}
