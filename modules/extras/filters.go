package extras

import (
	"fmt"
	"html"
	"main/modules/db"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	tg "github.com/xAmarnath/gogram/telegram"
	modules "main/modules"
)

const maxFiltersPerChat = 300

type compiledFilter struct {
	f *db.Filter
	t *trigger
}

type filterState struct {
	at       time.Time
	ttl      time.Duration
	filters  []*db.Filter
	compiled []compiledFilter
}

var (
	filtersMu    sync.RWMutex
	filtersCache = map[int64]*filterState{}
)

func invalidateFilters(chatID int64) {
	filtersMu.Lock()
	delete(filtersCache, chatID)
	filtersMu.Unlock()
}

func loadFilterState(chatID int64) *filterState {
	filtersMu.RLock()
	st, ok := filtersCache[chatID]
	filtersMu.RUnlock()
	if ok && time.Since(st.at) < st.ttl {
		return st
	}
	st = &filterState{at: time.Now(), ttl: triggerCacheTTL}
	list, err := db.GetAllFilters(chatID)
	if err != nil {
		st.ttl = triggerErrTTL
	}
	st.filters = list
	for _, f := range list {
		if t, err := compileTrigger(f.Keyword); err == nil {
			st.compiled = append(st.compiled, compiledFilter{f: f, t: t})
		}
	}
	// Longer plain keywords first so "good morning" wins over "morning"; regexes last.
	sort.SliceStable(st.compiled, func(i, j int) bool {
		a, b := st.compiled[i].t, st.compiled[j].t
		if a.isRegex() != b.isRegex() {
			return !a.isRegex()
		}
		return len(a.word) > len(b.word)
	})
	filtersMu.Lock()
	filtersCache[chatID] = st
	filtersMu.Unlock()
	return st
}

// formattedTail returns text[byteStart:] as HTML, keeping the sender's formatting entities.
func formattedTail(text string, entities []tg.MessageEntity, byteStart int) string {
	if byteStart < 0 || byteStart > len(text) {
		return ""
	}
	tail := text[byteStart:]
	shift := int32(utf16Len(text[:byteStart]))
	tailLen := int32(utf16Len(tail))
	var tags []tg.Tag
	for _, tag := range tg.ParseEntitiesToTags(entities) {
		switch tag.Type {
		case "mention":
			continue
		case "a":
			if tag.Attrs["href"] == "" || tag.Attrs["href"] == "mailto:" {
				continue
			}
		}
		start, end := tag.Offset-shift, tag.Offset+tag.Length-shift
		if end <= 0 || start >= tailLen {
			continue
		}
		start = max(start, 0)
		end = min(end, tailLen)
		tag.Offset, tag.Length = start, end-start
		tags = append(tags, tag)
	}
	return strings.TrimSpace(tg.InsertTagsIntoText(tail, tags))
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// argsStart is the byte offset in text right after the command token and following spaces.
func argsStart(text string) int {
	return len(text) - len(modules.CommandArgs(text))
}

type savedMedia struct {
	kind, fileID string
}

func mediaOfMessage(msg *tg.NewMessage) savedMedia {
	if msg == nil || !msg.IsMedia() || msg.File == nil || msg.File.FileID == "" {
		return savedMedia{}
	}
	kind := ""
	switch {
	case msg.Sticker() != nil:
		kind = "sticker"
	case msg.Animation() != nil:
		kind = "animation"
	case msg.Video() != nil:
		kind = "video"
	case msg.Voice() != nil:
		kind = "voice"
	case msg.Audio() != nil:
		kind = "audio"
	case msg.Photo() != nil:
		kind = "photo"
	case msg.Document() != nil:
		kind = "document"
	default:
		return savedMedia{}
	}
	return savedMedia{kind: kind, fileID: msg.File.FileID}
}

func FilterHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "change_info") {
		m.Reply("You need the <b>Change Info</b> admin right to add filters.")
		return nil
	}

	text := m.Text()
	args := modules.CommandArgs(text)
	if args == "" {
		m.Reply("<b>Usage:</b>\n<code>/filter keyword reply text</code>\n<code>/filter \"multi word\" reply text</code>\n<code>/filter regex:pattern reply text</code>\nOr reply to a message/media with <code>/filter keyword</code>.")
		return nil
	}
	keyRaw, rest := splitQuotedFirst(args)
	t, err := compileTrigger(keyRaw)
	if err != nil {
		m.Reply("Invalid keyword: " + html.EscapeString(err.Error()) + ".")
		return nil
	}
	key := normalizeTriggerKey(keyRaw)

	filter := &db.Filter{Keyword: key, AddedBy: m.SenderID()}
	if rest != "" {
		if idx := strings.LastIndex(text, rest); idx >= 0 {
			filter.Content = formattedTail(text, m.Message.Entities, idx)
		} else {
			filter.Content = html.EscapeString(rest)
		}
	}

	if m.IsReply() {
		reply, err := m.GetReplyMessage()
		if err != nil || reply == nil {
			m.Reply("I couldn't read the replied message. Please try again.")
			return nil
		}
		media := mediaOfMessage(reply)
		filter.MediaType, filter.FileID = media.kind, media.fileID
		if filter.Content == "" && reply.Message != nil {
			filter.Content = formattedTail(reply.Text(), reply.Message.Entities, 0)
		}
	}

	if filter.Content == "" && filter.FileID == "" {
		m.Reply("Please give a reply text, or reply to a message or media to use as the response.")
		return nil
	}

	chatID := m.ChatID()
	st := loadFilterState(chatID)
	exists := false
	for _, f := range st.filters {
		if f.Keyword == key {
			exists = true
			break
		}
	}
	if !exists && len(st.filters) >= maxFiltersPerChat {
		m.Reply(fmt.Sprintf("This chat already has the maximum of %d filters. Remove some with /stop first.", maxFiltersPerChat))
		return nil
	}

	if err := db.SaveFilter(chatID, filter); err != nil {
		m.Reply("I couldn't save the filter right now. Please try again.")
		return nil
	}
	invalidateFilters(chatID)

	kind := "Keyword"
	if t.isRegex() {
		kind = "Regex"
	}
	verb := "saved"
	if exists {
		verb = "updated"
	}
	m.Reply(fmt.Sprintf("Filter %s. %s: <code>%s</code>", verb, kind, html.EscapeString(key)))
	return nil
}

func findFilterKey(st *filterState, raw string) string {
	candidates := []string{normalizeTriggerKey(raw), strings.TrimSpace(raw), strings.ToLower(strings.TrimSpace(raw))}
	for _, c := range candidates {
		for _, f := range st.filters {
			if f.Keyword == c {
				return c
			}
		}
	}
	return ""
}

func StopFilterHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "change_info") {
		m.Reply("You need the <b>Change Info</b> admin right to remove filters.")
		return nil
	}
	args := modules.CommandArgs(m.Text())
	if args == "" {
		m.Reply("<b>Usage:</b> <code>/stop keyword</code> (use quotes for multi-word keywords, or <code>regex:pattern</code>)")
		return nil
	}
	raw := args
	if strings.HasPrefix(args, `"`) || strings.HasPrefix(args, "“") {
		raw, _ = splitQuotedFirst(args)
	}
	chatID := m.ChatID()
	key := findFilterKey(loadFilterState(chatID), raw)
	if key == "" {
		m.Reply(fmt.Sprintf("There's no filter for <code>%s</code>. See /filters.", html.EscapeString(raw)))
		return nil
	}
	if err := db.DeleteFilter(chatID, key); err != nil {
		m.Reply("I couldn't remove the filter right now. Please try again.")
		return nil
	}
	invalidateFilters(chatID)
	m.Reply(fmt.Sprintf("Filter removed: <code>%s</code>", html.EscapeString(key)))
	return nil
}

func ListFiltersHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	st := loadFilterState(m.ChatID())
	if len(st.filters) == 0 {
		m.Reply("No filters in this chat yet. Add one with <code>/filter keyword reply</code>.")
		return nil
	}
	list := append([]*db.Filter(nil), st.filters...)
	sort.Slice(list, func(i, j int) bool { return list[i].Keyword < list[j].Keyword })
	lines := make([]string, 0, len(list))
	media := 0
	for _, f := range list {
		marker := ""
		if f.FileID != "" {
			marker = " [" + html.EscapeString(f.MediaType) + "]"
			media++
		}
		lines = append(lines, " • <code>"+html.EscapeString(f.Keyword)+"</code>"+marker)
	}
	footer := fmt.Sprintf("\n<b>Total:</b> %d filters", len(list))
	if media > 0 {
		footer += fmt.Sprintf(" (%d with media)", media)
	}
	sendChunked(m, "<b>Filters in this chat:</b>\n\n", lines, footer)
	return nil
}

func StopAllFiltersHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "change_info") {
		m.Reply("You need the <b>Change Info</b> admin right to remove filters.")
		return nil
	}
	count := len(loadFilterState(m.ChatID()).filters)
	if count == 0 {
		m.Reply("There are no filters to delete.")
		return nil
	}
	b := tg.Button
	m.Reply(
		fmt.Sprintf("<b>Delete all %d filters?</b> This can't be undone.", count),
		&tg.SendOptions{
			ReplyMarkup: tg.NewKeyboard().AddRow(
				b.Data("Delete all", fmt.Sprintf("stopall_%d", m.SenderID())),
				b.Data("Cancel", fmt.Sprintf("cancelfilters_%d", m.SenderID())),
			).Build(),
		},
	)
	return nil
}

func StopAllFiltersCallback(c *tg.CallbackQuery) error {
	data := c.DataString()
	owner := ""
	if after, ok := strings.CutPrefix(data, "cancelfilters_"); ok {
		owner = after
	} else if after, ok := strings.CutPrefix(data, "stopall_"); ok {
		owner = after
	}
	if strconv.FormatInt(c.GetSenderID(), 10) != owner {
		c.Answer("This button isn't for you.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	if strings.HasPrefix(data, "cancelfilters_") {
		c.Edit("Cancelled.")
		return nil
	}
	if !modules.CallbackHasRight(c, "change_info") {
		c.Answer("You no longer have the Change Info admin right.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	chatID := c.ChatID
	count := len(loadFilterState(chatID).filters)
	if err := db.DeleteAllFilters(chatID); err != nil {
		c.Edit("I couldn't delete the filters right now. Please try again.")
		return nil
	}
	invalidateFilters(chatID)
	c.Edit(fmt.Sprintf("Deleted <b>%d</b> filters.", count))
	return nil
}

func FilterWatcher(m *tg.NewMessage) error {
	if m == nil || m.Message == nil || m.Message.Out || m.Action != nil || !modules.IsGroupChat(m) {
		return nil
	}
	text := m.Text()
	if text == "" || isCommandMessage(m) {
		return nil
	}
	st := loadFilterState(m.ChatID())
	if len(st.compiled) == 0 {
		return nil
	}
	lower := strings.ToLower(text)
	for _, cf := range st.compiled {
		if cf.t.match(text, lower) {
			sendFilterReply(m, cf.f)
			return nil
		}
	}
	return nil
}

func sendFilterReply(m *tg.NewMessage, f *db.Filter) {
	content, rows := parseButtons(f.Content)
	kb := buildKeyboard(rows)

	if f.FileID != "" {
		media, err := tg.ResolveBotFileID(f.FileID)
		if err == nil {
			opts := &tg.MediaOptions{ReplyMarkup: kb}
			captionFits := f.MediaType != "sticker" && utf8.RuneCountInString(content) <= 1024
			if captionFits {
				opts.Caption = content
			}
			if _, err := modules.TransferReplyMedia(m, media, opts); err == nil {
				if !captionFits && content != "" {
					m.Reply(content)
				}
				return
			}
		}
	}
	if content == "" {
		return
	}
	opts := &tg.SendOptions{}
	if kb != nil {
		opts.ReplyMarkup = kb
	}
	if _, err := m.Reply(content, opts); err != nil {
		m.Reply(html.EscapeString(content), opts)
	}
}

func registerFiltersHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:filter", FilterHandler)
	modules.OnCommand(c, "cmd:stop", StopFilterHandler)
	modules.OnCommand(c, "cmd:filters", ListFiltersHandler)
	modules.OnCommand(c, "cmd:stopall", StopAllFiltersHandler)
	c.On("callback:stopall_", StopAllFiltersCallback)
	c.On("callback:cancelfilters_", StopAllFiltersCallback)
	c.On(tg.OnNewMessage, FilterWatcher)
}

func init() {
	modules.QueueHandlerRegistration(registerFiltersHandlers)

	modules.Mods.AddModule("Filters", `<b>Filters</b>
Auto-reply when a message contains a keyword or matches a pattern. One reply per message; longer keywords win over shorter ones.

<b>Commands:</b>
 • <code>/filter &lt;keyword&gt; &lt;reply&gt;</code> - add or replace a filter. Formatting (bold, links...) is kept.
 • <code>/filter "&lt;multi word keyword&gt;" &lt;reply&gt;</code> - keyword with spaces.
 • <code>/filter regex:&lt;pattern&gt; &lt;reply&gt;</code> - trigger on a regular expression.
 • <code>/filter &lt;keyword&gt;</code> (reply to a message) - reply with that message's text, photo, video, GIF, sticker, voice, audio or file. Text after the keyword becomes the caption.
 • <code>/stop &lt;keyword&gt;</code> - remove a filter (<code>/stop regex:pattern</code> for regexes).
 • <code>/filters</code> - list all filters.
 • <code>/stopall</code> - remove every filter (asks for confirmation).
Adding/removing needs the Change Info admin right.

<b>Matching</b>
 • Keywords are case-insensitive whole words: <code>hello</code> triggers on "Hello there!" but not "helloworld". Works with any language.
 • <code>regex:</code> uses Go (RE2) syntax, case-insensitive, max 256 characters, checked against the first 4096 characters. Use <code>\s</code> instead of spaces in the pattern. Patterns matching everything are rejected.
 • Commands never trigger filters.

<b>Buttons:</b> add <code>[Text](https://link)</code> to the reply; start the text with <code>same:</code> to keep it on the previous row, e.g. <code>[Site](https://example.com) [same:Docs](https://example.com/docs)</code>. <code>[Rules](rules)</code> shows the chat rules.

<b>Examples:</b>
<code>/filter hello Hi there, welcome!</code>
<code>/filter "how are you" I'm a bot, but thanks!</code>
<code>/filter regex:^(hi|hey|yo)\b Hey!</code>
<code>/filter regex:discord\.gg/\w+ No invite links please.</code>
<code>/filter rules Read the [Rules](rules)</code>
<code>/stop hello</code>`)
}
