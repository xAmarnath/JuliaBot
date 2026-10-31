package extras

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"main/internal/mongostore"
	modules "main/modules"
	"main/modules/db"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	tg "github.com/xAmarnath/gogram/telegram"
)

var (
	buttonSyntax   = regexp.MustCompile(`\[([^\[\]]+)\]\(([^()\s]+)\)`)
	manyNewlines   = regexp.MustCompile(`\n{3,}`)
	htmlTagPattern = regexp.MustCompile(`<[^>]+>`)
)

// parseButtons extracts [Text](url), [same:Text](url) and [Text](rules) buttons from content.
// Anything else in brackets is left as text.
func parseButtons(content string) (string, [][]tg.KeyboardInlineButton) {
	var rows [][]tg.KeyboardInlineButton
	var row []tg.KeyboardInlineButton
	clean := buttonSyntax.ReplaceAllStringFunc(content, func(match string) string {
		sub := buttonSyntax.FindStringSubmatch(match)
		label := strings.TrimSpace(html.UnescapeString(htmlTagPattern.ReplaceAllString(sub[1], "")))
		action := html.UnescapeString(htmlTagPattern.ReplaceAllString(sub[2], ""))
		sameRow := false
		if after, ok := strings.CutPrefix(label, "same:"); ok {
			label, sameRow = strings.TrimSpace(after), true
		}
		if label == "" {
			return match
		}
		var btn tg.KeyboardInlineButton
		switch {
		case action == "rules":
			btn = tg.Button.Data(label, "rules_show")
		case strings.HasPrefix(action, "https://"), strings.HasPrefix(action, "http://"), strings.HasPrefix(action, "tg://"):
			btn = tg.Button.URL(label, action)
		default:
			return match
		}
		if sameRow && len(row) > 0 && len(row) < 8 {
			row = append(row, btn)
		} else {
			if len(row) > 0 {
				rows = append(rows, row)
			}
			row = []tg.KeyboardInlineButton{btn}
		}
		return ""
	})
	if len(row) > 0 {
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return content, nil
	}
	clean = manyNewlines.ReplaceAllString(strings.TrimSpace(clean), "\n\n")
	return clean, rows
}

func buildKeyboard(rows [][]tg.KeyboardInlineButton) *tg.ReplyInlineMarkup {
	if len(rows) == 0 {
		return nil
	}
	kb := tg.NewKeyboard()
	for _, row := range rows {
		kb.AddRow(row...)
	}
	return kb.Build()
}

func serializeButtonRows(rows [][]tg.KeyboardInlineButton) string {
	var lines []string
	for _, row := range rows {
		var parts []string
		for i, btn := range row {
			label := btn.Text
			if i > 0 {
				label = "same:" + label
			}
			switch b := btn.Type.(type) {
			case *tg.InlineButtonTypeURL:
				parts = append(parts, fmt.Sprintf("[%s](%s)", label, b.URL))
			case *tg.InlineButtonTypeCallback:
				if string(b.Data) == "rules_show" {
					parts = append(parts, fmt.Sprintf("[%s](rules)", label))
				}
			}
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	return strings.Join(lines, "\n")
}

func chatTitle(m *tg.NewMessage) string {
	if m.Channel != nil && m.Channel.Title != "" {
		return m.Channel.Title
	}
	if m.Chat != nil && m.Chat.Title != "" {
		return m.Chat.Title
	}
	return "this chat"
}

func plainFromHTML(s string) string {
	return strings.TrimSpace(html.UnescapeString(htmlTagPattern.ReplaceAllString(s, "")))
}

func SetRulesHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "change_info") {
		m.Reply("You need the <b>Change Info</b> admin right to set rules.")
		return nil
	}

	rules := &db.Rules{}
	text := m.Text()
	if modules.CommandArgs(text) != "" {
		rules.Content = formattedTail(text, m.Message.Entities, argsStart(text))
	}
	if m.IsReply() {
		reply, err := m.GetReplyMessage()
		if err != nil || reply == nil {
			m.Reply("I couldn't read the replied message. Please try again.")
			return nil
		}
		media := mediaOfMessage(reply)
		switch media.kind {
		case "photo", "document", "video", "animation":
			rules.MediaType, rules.FileID = media.kind, media.fileID
		}
		if rules.Content == "" && reply.Message != nil {
			rules.Content = formattedTail(reply.Text(), reply.Message.Entities, 0)
		}
	}

	if rules.Content == "" && rules.FileID == "" {
		m.Reply("<b>Usage:</b> <code>/setrules &lt;rules text&gt;</code> or reply to a message with <code>/setrules</code>.\n\n<b>Buttons:</b>\n<code>[Button](https://url)</code>\n<code>[same:Button 2](https://url2)</code> - same row\n<code>[Rules](rules)</code> - show rules popup")
		return nil
	}

	clean, rows := parseButtons(rules.Content)
	rules.Content = clean
	if len(rows) > 0 {
		rules.Buttons = serializeButtonRows(rows)
	}
	if utf8.RuneCountInString(rules.Content) > 4000 {
		m.Reply("The rules are too long; please keep them under 4000 characters.")
		return nil
	}

	if err := db.SetRulesWithMedia(m.ChatID(), rules); err != nil {
		m.Reply("I couldn't save the rules right now. Please try again.")
		return nil
	}
	tag := ""
	if rules.FileID != "" {
		tag = " (with media)"
	}
	m.Reply("Rules saved" + tag + ". Use /rules to view them.")
	return nil
}

func GetRulesHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	rules, err := db.GetRulesWithMedia(m.ChatID())
	if err != nil || rules == nil || (rules.Content == "" && rules.FileID == "") {
		m.Reply("No rules have been set for this chat.\nAdmins can set them with /setrules.")
		return nil
	}

	response := fmt.Sprintf("<b>Rules for %s:</b>\n\n%s", html.EscapeString(chatTitle(m)), rules.Content)
	var keyboard *tg.ReplyInlineMarkup
	if rules.Buttons != "" {
		_, rows := parseButtons(rules.Buttons)
		keyboard = buildKeyboard(rows)
	}

	if rules.FileID != "" {
		if media, err := tg.ResolveBotFileID(rules.FileID); err == nil {
			opts := &tg.MediaOptions{ReplyMarkup: keyboard}
			fits := utf8.RuneCountInString(plainFromHTML(response)) <= 1024
			if fits {
				opts.Caption = response
			}
			if _, err := modules.TransferReplyMedia(m, media, opts); err == nil {
				if !fits {
					m.Reply(response)
				}
				return nil
			}
		}
	}
	opts := &tg.SendOptions{}
	if keyboard != nil {
		opts.ReplyMarkup = keyboard
	}
	if _, err := m.Reply(response, opts); err != nil {
		m.Reply(html.EscapeString(plainFromHTML(response)), opts)
	}
	return nil
}

func ClearRulesHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "change_info") {
		m.Reply("You need the <b>Change Info</b> admin right to clear rules.")
		return nil
	}
	rules, _ := db.GetRulesWithMedia(m.ChatID())
	if rules == nil || (rules.Content == "" && rules.FileID == "") {
		m.Reply("No rules are set for this chat.")
		return nil
	}
	if err := db.DeleteRules(m.ChatID()); err != nil {
		m.Reply("I couldn't clear the rules right now. Please try again.")
		return nil
	}
	m.Reply("Rules cleared.")
	return nil
}

func RulesButtonCallback(c *tg.CallbackQuery) error {
	if c.DataString() != "rules_show" {
		return nil
	}
	rules, err := db.GetRulesWithMedia(c.ChatID)
	if err != nil || rules == nil || (rules.Content == "" && rules.FileID == "") {
		c.Answer("No rules have been set for this chat.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	plain := plainFromHTML(rules.Content)
	if plain != "" && utf8.RuneCountInString(plain) <= 190 {
		c.Answer(plain, &tg.CallbackOptions{Alert: true})
		return nil
	}
	if _, err := c.Client.SendMessage(c.GetSenderID(), "<b>Rules:</b>\n\n"+rules.Content); err == nil {
		c.Answer("I've sent you the rules in private.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	hint := "Start a private chat with me first, then tap again. Or use /rules in the group."
	if me := c.Client.Me(); me != nil && me.Username != "" {
		hint = "Start a private chat with @" + me.Username + " first, then tap again. Or use /rules in the group."
	}
	c.Answer(hint, &tg.CallbackOptions{Alert: true})
	return nil
}

func registerRuleHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:setrules", SetRulesHandler)
	modules.OnCommand(c, "cmd:rules", GetRulesHandler)
	modules.OnCommand(c, "cmd:clearrules", ClearRulesHandler)
	modules.OnCommand(c, "cmd:resetrules", ClearRulesHandler)
	c.On("callback:rules_show", RulesButtonCallback)
}

const tmpRulesBucket = "tmprules"

type tmpRule struct {
	ID        int64  `json:"id"`
	ChatID    int64  `json:"chat_id"`
	Peer      int64  `json:"peer,omitempty"`
	MsgID     int32  `json:"msg_id"`
	Text      string `json:"text"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedBy int64  `json:"created_by"`
}

// peerID returns the Bot-API chat ID; older records only stored the raw (supergroup) ID.
func (r *tmpRule) peerID() int64 {
	if r.Peer != 0 {
		return r.Peer
	}
	return modules.NormChatID(r.ChatID)
}

var (
	tmpRuleTimers   = make(map[int64]*time.Timer)
	tmpRuleTimersMu sync.Mutex
)

func tmpRuleKey(id int64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, uint64(id))
	return key
}

func saveTmpRule(r *tmpRule) error {
	database, err := db.GetDB()
	if err != nil {
		return err
	}
	return database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(tmpRulesBucket))
		if err != nil {
			return err
		}
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return b.Put(tmpRuleKey(r.ID), data)
	})
}

func deleteTmpRule(id int64) error {
	database, err := db.GetDB()
	if err != nil {
		return err
	}
	return database.Update(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(tmpRulesBucket))
		if b == nil {
			return nil
		}
		return b.Delete(tmpRuleKey(id))
	})
}

func getTmpRule(id int64) *tmpRule {
	database, err := db.GetDB()
	if err != nil {
		return nil
	}
	var r *tmpRule
	_ = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(tmpRulesBucket))
		if b == nil {
			return nil
		}
		v := b.Get(tmpRuleKey(id))
		if len(v) == 0 {
			return nil
		}
		var tmp tmpRule
		if json.Unmarshal(v, &tmp) == nil {
			r = &tmp
		}
		return nil
	})
	return r
}

func listTmpRules(match func(*tmpRule) bool) []*tmpRule {
	database, err := db.GetDB()
	if err != nil {
		return nil
	}
	var out []*tmpRule
	_ = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(tmpRulesBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var tmp tmpRule
			if json.Unmarshal(v, &tmp) == nil && (match == nil || match(&tmp)) {
				out = append(out, &tmp)
			}
			return nil
		})
	})
	return out
}

func scheduleTmpRule(r *tmpRule) {
	delay := max(time.Until(time.Unix(r.ExpiresAt, 0)), 0)
	id := r.ID
	tmpRuleTimersMu.Lock()
	if existing, ok := tmpRuleTimers[id]; ok {
		existing.Stop()
	}
	tmpRuleTimers[id] = time.AfterFunc(delay, func() { expireTmpRule(id) })
	tmpRuleTimersMu.Unlock()
}

func removeTmpRuleMessage(r *tmpRule) {
	if modules.Client == nil {
		return
	}
	_, _ = modules.Client.UnpinMessage(r.peerID(), r.MsgID)
	_, _ = modules.Client.DeleteMessages(r.peerID(), []int32{r.MsgID})
}

func expireTmpRule(id int64) {
	tmpRuleTimersMu.Lock()
	delete(tmpRuleTimers, id)
	tmpRuleTimersMu.Unlock()
	r := getTmpRule(id)
	if r == nil {
		return
	}
	removeTmpRuleMessage(r)
	_ = deleteTmpRule(id)
}

// formatSpan renders a duration as e.g. "1d 2h 5m".
func formatSpan(d time.Duration) string {
	d = d.Round(time.Second)
	var parts []string
	for _, u := range []struct {
		unit time.Duration
		name string
	}{{7 * 24 * time.Hour, "w"}, {24 * time.Hour, "d"}, {time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if n := d / u.unit; n > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", n, u.name))
			d -= n * u.unit
		}
	}
	if len(parts) == 0 {
		return "0s"
	}
	return strings.Join(parts, " ")
}

func TmpRuleHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "pin") {
		m.Reply("You need the <b>Pin Messages</b> admin right to post temporary rules.")
		return nil
	}
	durStr, text := modules.SplitFirstArg(modules.CommandArgs(m.Text()))
	if durStr == "" || text == "" {
		m.Reply("<b>Usage:</b> <code>/tmprule &lt;duration&gt; &lt;text&gt;</code>\n<b>Example:</b> <code>/tmprule 2h No memes until the event ends</code>")
		return nil
	}
	duration, err := modules.ParseTempDuration(durStr)
	if err != nil {
		m.Reply(modules.AdminFriendlyError(err, "post the rule"))
		return nil
	}
	if utf8.RuneCountInString(text) > 3500 {
		m.Reply("That rule is too long; keep it under 3500 characters.")
		return nil
	}

	body := fmt.Sprintf("<b>Temporary Rule</b>\n\n%s\n\n<i>Expires in %s</i>", html.EscapeString(text), formatSpan(duration))
	sent, err := m.Reply(body)
	if err != nil || sent == nil {
		m.Reply("I couldn't post the rule.")
		return nil
	}

	chat := m.ChannelID()
	if modules.BotHasRight(m.Client, chat, "pin") {
		if _, perr := m.Client.PinMessage(chat, sent.ID, &tg.PinOptions{Silent: true}); perr != nil {
			m.Reply("Rule posted, but I couldn't pin it: " + modules.AdminFriendlyError(perr, "pin it"))
		}
	} else {
		m.Reply("Rule posted. Give me the Pin Messages right if you want it pinned.")
	}

	r := &tmpRule{
		ID:        time.Now().UnixNano(),
		ChatID:    m.ChatID(),
		Peer:      chat,
		MsgID:     sent.ID,
		Text:      text,
		ExpiresAt: time.Now().Add(duration).Unix(),
		CreatedBy: m.SenderID(),
	}
	if err := saveTmpRule(r); err != nil {
		m.Reply("Note: I couldn't save this rule, so it won't expire if I restart.")
	}
	scheduleTmpRule(r)
	return nil
}

func TmpRulesListHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	chatID := m.ChatID()
	rules := listTmpRules(func(r *tmpRule) bool { return r.ChatID == chatID })
	if len(rules) == 0 {
		m.Reply("No temporary rules are active in this chat.")
		return nil
	}
	lines := make([]string, 0, len(rules))
	for _, r := range rules {
		preview := r.Text
		if utf8.RuneCountInString(preview) > 80 {
			preview = string([]rune(preview)[:80]) + "..."
		}
		lines = append(lines, fmt.Sprintf("<b>ID:</b> <code>%d</code>\n%s\n<i>Expires in %s</i>\n", r.ID, html.EscapeString(preview), formatSpan(max(time.Until(time.Unix(r.ExpiresAt, 0)), 0))))
	}
	sendChunked(m, "<b>Active temporary rules:</b>\n\n", lines, "")
	return nil
}

func RmTmpRuleHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "pin") {
		m.Reply("You need the <b>Pin Messages</b> admin right to remove temporary rules.")
		return nil
	}
	arg, _ := modules.SplitFirstArg(modules.CommandArgs(m.Text()))
	if arg == "" {
		m.Reply("<b>Usage:</b> <code>/rmtmprule &lt;id&gt;</code> (see /tmprules for IDs)")
		return nil
	}
	id, err := strconv.ParseInt(arg, 10, 64)
	if err != nil {
		m.Reply("That isn't a valid rule ID. See /tmprules.")
		return nil
	}
	r := getTmpRule(id)
	if r == nil || r.ChatID != m.ChatID() {
		m.Reply("There's no temporary rule with that ID in this chat.")
		return nil
	}
	tmpRuleTimersMu.Lock()
	if t, ok := tmpRuleTimers[id]; ok {
		t.Stop()
		delete(tmpRuleTimers, id)
	}
	tmpRuleTimersMu.Unlock()
	removeTmpRuleMessage(r)
	_ = deleteTmpRule(id)
	m.Reply("Temporary rule removed.")
	return nil
}

func rescheduleTmpRules() {
	now := time.Now().Unix()
	for _, r := range listTmpRules(nil) {
		if r.ExpiresAt <= now {
			go expireTmpRule(r.ID)
			continue
		}
		scheduleTmpRule(r)
	}
}

func registerTmpRulesHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:tmprule", TmpRuleHandler)
	modules.OnCommand(c, "cmd:tmprules", TmpRulesListHandler)
	modules.OnCommand(c, "cmd:rmtmprule", RmTmpRuleHandler)
	go rescheduleTmpRules()
}

func init() {
	modules.QueueHandlerRegistration(registerRuleHandlers)
	modules.QueueHandlerRegistration(registerTmpRulesHandlers)

	modules.Mods.AddModule("Rules", `<b>Rules</b>
Save the group rules once and show them on demand.

<b>Commands:</b>
 • <code>/rules</code> - show the rules.
 • <code>/setrules &lt;text&gt;</code> - set the rules. Formatting (bold, italic, links) is kept.
 • <code>/setrules</code> (reply to a message) - use that message's text, and its photo/video/GIF/file if it has one. Text after the command overrides the replied text.
 • <code>/clearrules</code> (or <code>/resetrules</code>) - delete the rules.
Setting and clearing needs the Change Info admin right.

<b>Buttons:</b>
 • <code>[Text](https://link)</code> - link button on a new row
 • <code>[same:Text](https://link)</code> - link button on the same row as the previous one
 • <code>[Rules](rules)</code> - button that shows the rules in a popup (or in private if they're long)

<b>Example:</b>
<code>/setrules 1. Be nice
2. No spam or ads
[Full rules](https://example.com/rules)</code>`)

	modules.Mods.AddModule("TempRules", `<b>Temporary Rules</b>
Post a rule that is pinned for a limited time, then automatically unpinned and deleted (survives restarts).

<b>Commands:</b>
 • <code>/tmprule &lt;duration&gt; &lt;text&gt;</code> - post and pin a temporary rule (Pin Messages right needed).
 • <code>/tmprules</code> - list active temporary rules with their IDs.
 • <code>/rmtmprule &lt;id&gt;</code> - remove one early (Pin Messages right needed).

<b>Durations:</b> 1m to 366d, e.g. <code>30m</code>, <code>2h</code>, <code>1d</code>, <code>1w</code>, <code>1h30m</code>.

<b>Example:</b> <code>/tmprule 2h No off-topic during the AMA</code>`)
}
