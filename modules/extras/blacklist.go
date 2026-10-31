package extras

import (
	"encoding/base64"
	"fmt"
	"html"
	"main/modules/db"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	modules "main/modules"

	tg "github.com/xAmarnath/gogram/telegram"
)

// ------------------ Trigger matching (shared by blacklist and filters) ------------------

const (
	regexTriggerPrefix = "regex:"
	maxTriggerLen      = 256
	maxMatchInput      = 4096
	maxBlacklistItems  = 500
	triggerCacheTTL    = 10 * time.Minute
	triggerErrTTL      = time.Minute
)

type trigger struct {
	key  string
	word string
	re   *regexp.Regexp
}

// regexTriggerPattern extracts the pattern from "regex:<p>" or the legacy "/<p>/" form.
func regexTriggerPattern(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if len(s) >= len(regexTriggerPrefix) && strings.EqualFold(s[:len(regexTriggerPrefix)], regexTriggerPrefix) {
		return strings.TrimSpace(s[len(regexTriggerPrefix):]), true
	}
	if len(s) > 2 && s[0] == '/' && s[len(s)-1] == '/' {
		return s[1 : len(s)-1], true
	}
	return "", false
}

// normalizeTriggerKey returns the storage key for user input: regexes keep their case, words are lowercased.
func normalizeTriggerKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if p, ok := regexTriggerPattern(raw); ok {
		return regexTriggerPrefix + p
	}
	return strings.ToLower(strings.Join(strings.Fields(raw), " "))
}

func compileTrigger(raw string) (*trigger, error) {
	raw = strings.TrimSpace(raw)
	if p, ok := regexTriggerPattern(raw); ok {
		if p == "" {
			return nil, fmt.Errorf("the regex pattern is empty")
		}
		if len(p) > maxTriggerLen {
			return nil, fmt.Errorf("the regex is too long (max %d characters)", maxTriggerLen)
		}
		re, err := modules.ValidateUserRegex(p)
		if err != nil {
			return nil, err
		}
		return &trigger{key: raw, re: re}, nil
	}
	word := strings.ToLower(strings.Join(strings.Fields(raw), " "))
	if word == "" {
		return nil, fmt.Errorf("the word is empty")
	}
	if len(word) > maxTriggerLen {
		return nil, fmt.Errorf("the word is too long (max %d characters)", maxTriggerLen)
	}
	if utf8.RuneCountInString(word) < 2 && !isNoSpaceScript(firstRune(word)) {
		return nil, fmt.Errorf("the word must be at least 2 characters")
	}
	return &trigger{key: raw, word: word}, nil
}

func (t *trigger) isRegex() bool { return t.re != nil }

// match expects lower = strings.ToLower(text).
func (t *trigger) match(text, lower string) bool {
	if t.re != nil {
		return t.re.MatchString(truncateUTF8(text, maxMatchInput))
	}
	return containsWord(lower, t.word)
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func firstRune(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}

func lastRune(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r)
}

// Scripts written without spaces can't use word boundaries.
func isNoSpaceScript(r rune) bool {
	return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Thai, unicode.Lao, unicode.Khmer, unicode.Myanmar)
}

// containsWord reports whether word occurs in text as a whole word. Boundaries are only
// enforced on edges where the word itself starts/ends with a word character.
func containsWord(text, word string) bool {
	if word == "" {
		return false
	}
	needStart := isWordRune(firstRune(word)) && !isNoSpaceScript(firstRune(word))
	needEnd := isWordRune(lastRune(word)) && !isNoSpaceScript(lastRune(word))
	for from := 0; from <= len(text)-len(word); {
		i := strings.Index(text[from:], word)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(word)
		okStart := !needStart || start == 0 || !isWordRune(lastRune(text[:start]))
		okEnd := !needEnd || end == len(text) || !isWordRune(firstRune(text[end:]))
		if okStart && okEnd {
			return true
		}
		_, size := utf8.DecodeRuneInString(text[start:])
		from = start + size
	}
	return false
}

// splitQuotedFirst splits `"multi word" rest` or `word rest`.
func splitQuotedFirst(s string) (string, string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) || strings.HasPrefix(s, "“") {
		open := `"`
		if strings.HasPrefix(s, "“") {
			open = "“"
		}
		body := s[len(open):]
		if j := strings.IndexAny(body, "\"”"); j >= 0 {
			_, size := utf8.DecodeRuneInString(body[j:])
			return strings.TrimSpace(body[:j]), strings.TrimSpace(body[j+size:])
		}
	}
	return modules.SplitFirstArg(s)
}

func isCommandMessage(m *tg.NewMessage) bool {
	if m.Message == nil {
		return false
	}
	for _, e := range m.Message.Entities {
		if bc, ok := e.(*tg.MessageEntityBotCommand); ok && bc.Offset == 0 {
			return true
		}
	}
	return false
}

// mediaUniqueID identifies the underlying file so re-sends of the same sticker/photo match.
func mediaUniqueID(m *tg.NewMessage) int64 {
	if m == nil || m.Message == nil || m.Message.Media == nil {
		return 0
	}
	if p := m.Photo(); p != nil {
		return p.ID
	}
	if d := m.Document(); d != nil {
		return d.ID
	}
	return 0
}

func fileIDUniqueID(fileID string) int64 {
	fileID = strings.TrimRight(fileID, "=")
	data, err := base64.RawURLEncoding.DecodeString(fileID)
	if err != nil {
		return 0
	}
	if len(data) == 20 || len(data) == 28 {
		id, _, kind, dc, _ := tg.UnpackBotFileID(fileID)
		if dc > 0 {
			switch kind {
			case 2, 3, 4, 5, 8, 9, 10, 13:
				return id
			}
		}
	}
	parts := strings.Split(string(data), "_")
	if len(parts) != 4 && len(parts) != 5 {
		return 0
	}
	values := make([]int64, len(parts))
	for i, part := range parts {
		values[i], err = strconv.ParseInt(part, 10, 64)
		if err != nil {
			return 0
		}
	}
	if values[1] <= 0 {
		return 0
	}
	switch values[0] {
	case 2, 3, 4, 5, 8, 9, 10, 13:
		return values[2]
	}
	return 0
}

// sendChunked replies with lines split across messages that fit Telegram's 4096-char limit.
func sendChunked(m *tg.NewMessage, header string, lines []string, footer string) {
	const limit = 3800
	var b strings.Builder
	b.WriteString(header)
	for _, line := range lines {
		if b.Len()+len(line)+1 > limit {
			m.Reply(b.String())
			b.Reset()
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if b.Len()+len(footer) > limit {
		m.Reply(b.String())
		b.Reset()
	}
	b.WriteString(footer)
	if strings.TrimSpace(b.String()) != "" {
		m.Reply(b.String())
	}
}

// ------------------ Blacklist cache ------------------

type blacklistState struct {
	at       time.Time
	ttl      time.Duration
	entries  []*db.BlacklistEntry
	triggers []*trigger
	media    map[int64]bool
	settings db.BlacklistSettings
}

var (
	blacklistMu    sync.RWMutex
	blacklistCache = map[int64]*blacklistState{}
)

func invalidateBlacklist(chatID int64) {
	blacklistMu.Lock()
	delete(blacklistCache, chatID)
	blacklistMu.Unlock()
}

func loadBlacklistState(chatID int64) *blacklistState {
	blacklistMu.RLock()
	st, ok := blacklistCache[chatID]
	blacklistMu.RUnlock()
	if ok && time.Since(st.at) < st.ttl {
		return st
	}
	st = &blacklistState{at: time.Now(), ttl: triggerCacheTTL, media: map[int64]bool{}, settings: db.BlacklistSettings{Action: db.ActionDelete}}
	entries, err := db.GetBlacklist(chatID)
	settings, serr := db.GetBlacklistSettings(chatID)
	if err != nil || serr != nil {
		st.ttl = triggerErrTTL
	}
	if settings != nil {
		st.settings = *settings
	}
	st.entries = entries
	for _, e := range entries {
		if e.FileID != "" {
			if id := fileIDUniqueID(e.FileID); id != 0 {
				st.media[id] = true
			}
			continue
		}
		if t, err := compileTrigger(e.Word); err == nil {
			st.triggers = append(st.triggers, t)
		}
	}
	blacklistMu.Lock()
	blacklistCache[chatID] = st
	blacklistMu.Unlock()
	return st
}

func (st *blacklistState) match(m *tg.NewMessage) (string, bool) {
	if len(st.media) > 0 {
		if id := mediaUniqueID(m); id != 0 && st.media[id] {
			return "media", true
		}
	}
	text := m.Text()
	if text == "" || len(st.triggers) == 0 {
		return "", false
	}
	lower := strings.ToLower(text)
	for _, t := range st.triggers {
		if t.match(text, lower) {
			return t.key, true
		}
	}
	return "", false
}

func findBlacklistEntry(chatID int64, raw string) *db.BlacklistEntry {
	entries, _ := db.GetBlacklist(chatID)
	candidates := []string{normalizeTriggerKey(raw), strings.TrimSpace(raw), strings.ToLower(strings.TrimSpace(raw))}
	if p, ok := regexTriggerPattern(raw); ok {
		candidates = append(candidates, "/"+p+"/")
	}
	for _, c := range candidates {
		for _, e := range entries {
			if e.FileID == "" && e.Word == c {
				return e
			}
		}
	}
	return nil
}

// ------------------ Blacklist commands ------------------

func blacklistAdminGate(m *tg.NewMessage) bool {
	if !modules.RequireGroup(m) {
		return false
	}
	if !modules.SenderHasRight(m, "ban") {
		m.Reply("You need the <b>Ban Users</b> admin right to change the blacklist.")
		return false
	}
	return true
}

func replyMediaFileID(m *tg.NewMessage) (*tg.NewMessage, string) {
	if !m.IsReply() {
		return nil, ""
	}
	reply, err := m.GetReplyMessage()
	if err != nil || reply == nil || !reply.IsMedia() || reply.File == nil || mediaUniqueID(reply) == 0 {
		return nil, ""
	}
	return reply, reply.File.FileID
}

func AddBlacklistHandler(m *tg.NewMessage) error {
	if !blacklistAdminGate(m) {
		return nil
	}
	chatID := m.ChatID()
	raw := modules.CommandArgs(m.Text())

	if raw == "" {
		reply, fileID := replyMediaFileID(m)
		if reply == nil {
			m.Reply("<b>Usage:</b>\n<code>/addbl word</code>\n<code>/addbl regex:pattern</code>\nOne item per line to add several, or reply to a sticker/photo/file with <code>/addbl</code>.")
			return nil
		}
		if fileID == "" {
			m.Reply("I couldn't read that media's file ID.")
			return nil
		}
		uid := mediaUniqueID(reply)
		for _, e := range loadBlacklistState(chatID).entries {
			if e.FileID != "" && fileIDUniqueID(e.FileID) == uid {
				m.Reply("This media is already blacklisted.")
				return nil
			}
		}
		link := ""
		if cid := m.ChannelID(); cid < -1000000000000 {
			link = fmt.Sprintf("https://t.me/c/%d/%d", chatID, reply.ID)
		}
		entry := &db.BlacklistEntry{Word: fileID, FileID: fileID, MessageLink: link, AddedBy: m.SenderID()}
		if err := db.AddBlacklist(chatID, entry); err != nil {
			m.Reply("I couldn't save the blacklist right now. Please try again.")
			return nil
		}
		invalidateBlacklist(chatID)
		m.Reply("Media added to the blacklist. Matching media will be deleted, including posts from admins.")
		return nil
	}

	st := loadBlacklistState(chatID)
	existing := map[string]bool{}
	for _, e := range st.entries {
		existing[e.Word] = true
	}
	count := len(st.entries)

	var added, skipped, failed []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		t, err := compileTrigger(line)
		if err != nil {
			failed = append(failed, fmt.Sprintf("<code>%s</code>: %s", html.EscapeString(line), html.EscapeString(err.Error())))
			continue
		}
		key := normalizeTriggerKey(line)
		if existing[key] || (t.isRegex() && existing["/"+strings.TrimPrefix(key, regexTriggerPrefix)+"/"]) {
			skipped = append(skipped, "<code>"+html.EscapeString(key)+"</code>")
			continue
		}
		if count >= maxBlacklistItems {
			failed = append(failed, fmt.Sprintf("<code>%s</code>: blacklist is full (max %d items)", html.EscapeString(key), maxBlacklistItems))
			continue
		}
		if err := db.AddBlacklist(chatID, &db.BlacklistEntry{Word: key, AddedBy: m.SenderID()}); err != nil {
			failed = append(failed, "<code>"+html.EscapeString(key)+"</code>: couldn't save")
			continue
		}
		existing[key] = true
		count++
		added = append(added, "<code>"+html.EscapeString(key)+"</code>")
	}
	invalidateBlacklist(chatID)

	var out []string
	if len(added) > 0 {
		out = append(out, "<b>Added to blacklist:</b> "+strings.Join(added, ", "))
	}
	if len(skipped) > 0 {
		out = append(out, "<b>Already blacklisted:</b> "+strings.Join(skipped, ", "))
	}
	if len(failed) > 0 {
		out = append(out, "<b>Rejected:</b>\n"+strings.Join(failed, "\n"))
	}
	if len(out) == 0 {
		out = append(out, "Nothing to add.")
	}
	sendChunked(m, "", out, "")
	return nil
}

func RemoveBlacklistHandler(m *tg.NewMessage) error {
	if !blacklistAdminGate(m) {
		return nil
	}
	chatID := m.ChatID()
	raw := modules.CommandArgs(m.Text())

	if raw == "" {
		reply, _ := replyMediaFileID(m)
		if reply == nil {
			m.Reply("<b>Usage:</b> <code>/rmbl word</code>, <code>/rmbl regex:pattern</code> (one per line), or reply to blacklisted media.")
			return nil
		}
		uid := mediaUniqueID(reply)
		for _, e := range loadBlacklistState(chatID).entries {
			if e.FileID != "" && fileIDUniqueID(e.FileID) == uid {
				if err := db.RemoveBlacklist(chatID, e.Word); err != nil {
					m.Reply("I couldn't update the blacklist right now. Please try again.")
					return nil
				}
				invalidateBlacklist(chatID)
				m.Reply("Media removed from the blacklist.")
				return nil
			}
		}
		m.Reply("That media isn't blacklisted.")
		return nil
	}

	var removed, missing []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		e := findBlacklistEntry(chatID, line)
		if e == nil {
			missing = append(missing, "<code>"+html.EscapeString(line)+"</code>")
			continue
		}
		if err := db.RemoveBlacklist(chatID, e.Word); err != nil {
			missing = append(missing, "<code>"+html.EscapeString(line)+"</code> (couldn't save)")
			continue
		}
		removed = append(removed, "<code>"+html.EscapeString(e.Word)+"</code>")
	}
	invalidateBlacklist(chatID)

	var out []string
	if len(removed) > 0 {
		out = append(out, "<b>Removed from blacklist:</b> "+strings.Join(removed, ", "))
	}
	if len(missing) > 0 {
		out = append(out, "<b>Not in blacklist:</b> "+strings.Join(missing, ", "))
	}
	sendChunked(m, "", out, "")
	return nil
}

func blacklistActionLabel(s db.BlacklistSettings) string {
	label := string(s.Action)
	if label == "" {
		label = string(db.ActionDelete)
	}
	if s.Duration != "" && (s.Action == db.ActionTBan || s.Action == db.ActionTMute) {
		label += " (" + html.EscapeString(s.Duration) + ")"
	}
	return label
}

func ListBlacklistHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	st := loadBlacklistState(m.ChatID())
	if len(st.entries) == 0 {
		m.Reply("No blacklisted items in this chat.\nAdmins can add some with <code>/addbl word</code>.")
		return nil
	}
	entries := append([]*db.BlacklistEntry(nil), st.entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Word < entries[j].Word })

	var lines []string
	words, regexes, media := 0, 0, 0
	for _, e := range entries {
		if e.FileID != "" {
			media++
			continue
		}
		if _, ok := regexTriggerPattern(e.Word); ok {
			regexes++
		} else {
			words++
		}
		lines = append(lines, " • <code>"+html.EscapeString(e.Word)+"</code>")
	}
	if media > 0 {
		lines = append(lines, fmt.Sprintf(" • %d blacklisted media (see /rmblmenu)", media))
	}
	footer := fmt.Sprintf("\nTotal: <b>%d</b> (%d words, %d regex, %d media)\nAction: <b>%s</b>", len(entries), words, regexes, media, blacklistActionLabel(st.settings))
	sendChunked(m, "<b>Blacklisted items:</b>\n\n", lines, footer)
	return nil
}

func SetBlacklistActionHandler(m *tg.NewMessage) error {
	if !blacklistAdminGate(m) {
		return nil
	}
	chatID := m.ChatID()
	args := strings.Fields(strings.ToLower(modules.CommandArgs(m.Text())))
	if len(args) == 0 {
		st := loadBlacklistState(chatID)
		m.Reply(fmt.Sprintf(`<b>Blacklist action</b>

Current: <b>%s</b>

<b>Usage:</b> <code>/setblaction &lt;action&gt; [duration]</code>
 • <code>delete</code> - only delete the message (default)
 • <code>ban</code> - delete and ban the sender
 • <code>mute</code> - delete and mute the sender
 • <code>tban 1d</code> - delete and ban for a time
 • <code>tmute 2h</code> - delete and mute for a time

Durations: 30m, 2h, 3d, 1w`, blacklistActionLabel(st.settings)))
		return nil
	}

	settings := &db.BlacklistSettings{}
	switch args[0] {
	case "delete", "del":
		settings.Action = db.ActionDelete
	case "ban":
		settings.Action = db.ActionBan
	case "mute":
		settings.Action = db.ActionMute
	case "tban", "tmute":
		if len(args) < 2 {
			m.Reply(fmt.Sprintf("%s needs a duration, e.g. <code>/setblaction %s 1h</code>", args[0], args[0]))
			return nil
		}
		if _, err := modules.ParseTempDuration(args[1]); err != nil {
			m.Reply(modules.AdminFriendlyError(err, "set the action"))
			return nil
		}
		settings.Action = db.BlacklistAction(args[0])
		settings.Duration = args[1]
	default:
		m.Reply("Unknown action. Use one of: <code>delete</code>, <code>ban</code>, <code>mute</code>, <code>tban</code>, <code>tmute</code>.")
		return nil
	}

	if err := db.SetBlacklistSettings(chatID, settings); err != nil {
		m.Reply("I couldn't save the setting right now. Please try again.")
		return nil
	}
	invalidateBlacklist(chatID)
	m.Reply("Blacklist action set to <b>" + blacklistActionLabel(*settings) + "</b>.")
	return nil
}

var (
	blNoticeMu   sync.Mutex
	blNoticeLast = map[string]time.Time{}
)

// shouldNotify throttles action notices so a flood of offending messages produces one reply.
func shouldNotify(chatID, userID int64) bool {
	key := strconv.FormatInt(chatID, 10) + ":" + strconv.FormatInt(userID, 10)
	blNoticeMu.Lock()
	defer blNoticeMu.Unlock()
	now := time.Now()
	if t, ok := blNoticeLast[key]; ok && now.Sub(t) < 30*time.Second {
		return false
	}
	if len(blNoticeLast) > 5000 {
		blNoticeLast = map[string]time.Time{}
	}
	blNoticeLast[key] = now
	return true
}

func BlacklistWatcher(m *tg.NewMessage) error {
	if m == nil || m.Message == nil || m.Message.Out || m.Action != nil || !modules.IsGroupChat(m) {
		return nil
	}
	st := loadBlacklistState(m.ChatID())
	if len(st.triggers) == 0 && len(st.media) == 0 {
		return nil
	}
	if _, ok := st.match(m); !ok {
		return nil
	}
	chat := m.ChannelID()
	if _, err := m.Delete(); err != nil {
		return fmt.Errorf("blacklist: delete message %d in chat %d: %w", m.ID, chat, err)
	}

	action := st.settings.Action
	if action == "" || action == db.ActionDelete {
		return nil
	}
	senderID := m.SenderID()
	if modules.IsAnonAdmin(m) || senderID > 0 && modules.IsChatAdmin(m.Client, chat, senderID) {
		return nil
	}
	target, err := modules.TargetFromMessage(m, m)
	if err != nil || !modules.BotHasRight(m.Client, chat, "ban") {
		return nil
	}

	var d time.Duration
	if action == db.ActionTBan || action == db.ActionTMute {
		d, err = modules.ParseTempDuration(st.settings.Duration)
		if err != nil {
			d = time.Hour
		}
	}
	var verb string
	switch action {
	case db.ActionBan, db.ActionTBan:
		err, verb = modules.BanMember(m.Client, chat, target.Peer, d), "banned"
	case db.ActionMute, db.ActionTMute:
		if target.IsChannel {
			return nil
		}
		err, verb = modules.MuteMember(m.Client, chat, target.Peer, d), "muted"
	default:
		return nil
	}
	if err != nil || !shouldNotify(chat, target.ID) {
		return nil
	}
	msg := fmt.Sprintf("%s was %s for using a blacklisted word", target.Mention(), verb)
	if d > 0 {
		msg += " for " + formatSpan(d)
	}
	m.Respond(msg + ".")
	return nil
}

func ClearBlacklistHandler(m *tg.NewMessage) error {
	if !blacklistAdminGate(m) {
		return nil
	}
	count := len(loadBlacklistState(m.ChatID()).entries)
	if count == 0 {
		m.Reply("The blacklist is already empty.")
		return nil
	}
	b := tg.Button
	m.Reply(
		fmt.Sprintf("<b>Clear all %d blacklisted items?</b> This can't be undone.", count),
		&tg.SendOptions{
			ReplyMarkup: tg.NewKeyboard().AddRow(
				b.Data("Yes, clear all", fmt.Sprintf("clearbl_%d", m.SenderID())),
				b.Data("Cancel", fmt.Sprintf("cancelbl_%d", m.SenderID())),
			).Build(),
		},
	)
	return nil
}

func BlacklistRemovalMenu(m *tg.NewMessage) error {
	if !blacklistAdminGate(m) {
		return nil
	}
	st := loadBlacklistState(m.ChatID())
	if len(st.entries) == 0 {
		m.Reply("The blacklist is empty.")
		return nil
	}

	var media []*db.BlacklistEntry
	words := 0
	for _, e := range st.entries {
		if e.FileID != "" {
			media = append(media, e)
		} else {
			words++
		}
	}
	if len(media) == 0 {
		m.Reply(fmt.Sprintf("No blacklisted media. There are <b>%d</b> blacklisted words; remove them with <code>/rmbl word</code>.", words))
		return nil
	}

	shown := min(len(media), 20)
	var resp strings.Builder
	fmt.Fprintf(&resp, "<b>Blacklisted media (%d):</b>\n\n", len(media))
	kb := tg.NewKeyboard()
	var row []tg.KeyboardInlineButton
	for i := 0; i < shown; i++ {
		e := media[i]
		if e.MessageLink != "" {
			fmt.Fprintf(&resp, "%d. <a href=\"%s\">View media</a>\n", i+1, html.EscapeString(e.MessageLink))
		} else {
			fmt.Fprintf(&resp, "%d. Media (no link)\n", i+1)
		}
		btn := tg.Button.Data(fmt.Sprintf("Remove %d", i+1), fmt.Sprintf("rmblmedia_%d", fileIDUniqueID(e.FileID)))
		btn.Style = &tg.KeyboardButtonStyle{BgDanger: true}
		row = append(row, btn)
		if len(row) == 2 {
			kb.AddRow(row...)
			row = nil
		}
	}
	if len(row) > 0 {
		kb.AddRow(row...)
	}
	if len(media) > shown {
		fmt.Fprintf(&resp, "\n<i>Showing %d of %d. Reply to media with /rmbl to remove others.</i>\n", shown, len(media))
	}
	fmt.Fprintf(&resp, "\nWords: <b>%d</b> (remove with <code>/rmbl word</code>)", words)
	m.Reply(resp.String(), &tg.SendOptions{ReplyMarkup: kb.Build()})
	return nil
}

func HandleBlacklistMediaRemoval(c *tg.CallbackQuery) error {
	data := strings.TrimPrefix(c.DataString(), "rmblmedia_")
	if strings.Contains(data, "_") {
		c.Answer("This menu is outdated. Run /rmblmenu again.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	uid, err := strconv.ParseInt(data, 10, 64)
	if err != nil {
		c.Answer("Invalid button.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	if !modules.CallbackHasRight(c, "ban") {
		c.Answer("You need the Ban Users admin right to do this.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	chatID := c.ChatID
	for _, e := range loadBlacklistState(chatID).entries {
		if e.FileID != "" && fileIDUniqueID(e.FileID) == uid {
			if err := db.RemoveBlacklist(chatID, e.Word); err != nil {
				c.Answer("I couldn't update the blacklist. Try again.", &tg.CallbackOptions{Alert: true})
				return nil
			}
			invalidateBlacklist(chatID)
			c.Answer("Media removed from the blacklist.")
			return nil
		}
	}
	c.Answer("That media is no longer blacklisted.", &tg.CallbackOptions{Alert: true})
	return nil
}

func ClearBlacklistCallback(c *tg.CallbackQuery) error {
	data := c.DataString()
	owner := ""
	if after, ok := strings.CutPrefix(data, "cancelbl_"); ok {
		owner = after
	} else if after, ok := strings.CutPrefix(data, "clearbl_"); ok {
		owner = after
	}
	if strconv.FormatInt(c.GetSenderID(), 10) != owner {
		c.Answer("This button isn't for you.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	if strings.HasPrefix(data, "cancelbl_") {
		c.Edit("Cancelled.")
		return nil
	}
	if !modules.CallbackHasRight(c, "ban") {
		c.Answer("You no longer have the Ban Users admin right.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	chatID := c.ChatID
	count := len(loadBlacklistState(chatID).entries)
	if err := db.ClearBlacklist(chatID); err != nil {
		c.Edit("I couldn't clear the blacklist right now. Please try again.")
		return nil
	}
	invalidateBlacklist(chatID)
	c.Edit(fmt.Sprintf("Cleared <b>%d</b> blacklisted items.", count))
	return nil
}

func registerBlacklistHandlers() {
	c := modules.Client
	if c == nil {
		return
	}
	modules.OnCommand(c, "cmd:addbl", AddBlacklistHandler)
	modules.OnCommand(c, "cmd:addblacklist", AddBlacklistHandler)
	modules.OnCommand(c, "cmd:rmbl", RemoveBlacklistHandler)
	modules.OnCommand(c, "cmd:rmblacklist", RemoveBlacklistHandler)
	modules.OnCommand(c, "cmd:unblacklist", RemoveBlacklistHandler)
	modules.OnCommand(c, "cmd:listbl", ListBlacklistHandler)
	modules.OnCommand(c, "cmd:blacklist", ListBlacklistHandler)
	modules.OnCommand(c, "cmd:rmblmenu", BlacklistRemovalMenu)
	modules.OnCommand(c, "cmd:setblaction", SetBlacklistActionHandler)
	modules.OnCommand(c, "cmd:blaction", SetBlacklistActionHandler)
	modules.OnCommand(c, "cmd:clearbl", ClearBlacklistHandler)
	c.On("callback:clearbl_", ClearBlacklistCallback)
	c.On("callback:cancelbl_", ClearBlacklistCallback)
	c.On("callback:rmblmedia_", HandleBlacklistMediaRemoval)
	c.On(tg.OnNewMessage, BlacklistWatcher)
	c.On(tg.OnEditMessage, BlacklistWatcher)
}

func init() {
	modules.QueueHandlerRegistration(registerBlacklistHandlers)

	modules.Mods.AddModule("Blacklist", `<b>Blacklist</b>
Automatically delete messages containing banned words, patterns or media, including posts from admins. Optional bans and mutes apply only to non-admin members.

<b>Commands</b> (Ban Users right needed to change):
 • <code>/addbl &lt;word or phrase&gt;</code> - blacklist a word/phrase. Put several on separate lines to add many at once.
 • <code>/addbl regex:&lt;pattern&gt;</code> - blacklist a regular expression.
 • <code>/addbl</code> (reply to a sticker/photo/GIF/file) - blacklist that media.
 • <code>/rmbl &lt;word | regex:pattern&gt;</code> - remove items (one per line), or reply to media.
 • <code>/blacklist</code> or <code>/listbl</code> - list everything that is blacklisted.
 • <code>/rmblmenu</code> - buttons to remove blacklisted media.
 • <code>/setblaction &lt;action&gt; [duration]</code> - what to do to offenders.
 • <code>/clearbl</code> - remove every item (asks for confirmation).
Aliases: /addblacklist, /rmblacklist, /unblacklist, /blaction.

<b>Matching</b>
 • Words match case-insensitively as whole words: <code>bad</code> matches "so BAD!" but not "badge". Phrases and non-Latin scripts work too.
 • <code>regex:</code> patterns use Go (RE2) syntax, are case-insensitive, max 256 characters, and are checked against the first 4096 characters of a message. Patterns that match everything are rejected. The old <code>/pattern/</code> form is still accepted.

<b>Actions</b>
 • <code>delete</code> - delete only (default)
 • <code>ban</code> / <code>mute</code> - delete and ban/mute
 • <code>tban &lt;time&gt;</code> / <code>tmute &lt;time&gt;</code> - temporary ban/mute (e.g. 30m, 2h, 3d, 1w)

<b>Examples</b>
<code>/addbl casino</code>
<code>/addbl regex:t\.me/\w+</code>
<code>/addbl regex:fr[e3]{2}\s*m[o0]ney</code>
<code>/rmbl casino</code>
<code>/setblaction tmute 1h</code>

I need the Delete Messages right (and Ban Users for ban/mute actions).`)
}
