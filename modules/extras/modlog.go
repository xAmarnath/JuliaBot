package extras

import (
	"fmt"
	"html"
	"main/modules/db"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
	modules "main/modules"
)

const (
	modlogBucket  = "modlog"
	kickBanWindow = 3 * time.Minute
)

var (
	modlogMu    sync.RWMutex
	modlogCache = make(map[int64]int64)

	modlogKicksMu sync.Mutex
	modlogKicks   = make(map[string]time.Time)
)

func setModlogChat(srcChat, logChat int64) error {
	d, err := db.GetDB()
	if err != nil {
		return err
	}
	err = d.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(modlogBucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(strconv.FormatInt(srcChat, 10)), []byte(strconv.FormatInt(logChat, 10)))
	})
	if err != nil {
		return err
	}
	modlogMu.Lock()
	modlogCache[srcChat] = logChat
	modlogMu.Unlock()
	return nil
}

// getModlogChat returns the log chat for srcChat (an m.ChatID() key). Results, including "none", are cached.
func getModlogChat(srcChat int64) (int64, bool) {
	modlogMu.RLock()
	v, ok := modlogCache[srcChat]
	modlogMu.RUnlock()
	if ok {
		return v, v != 0
	}
	d, err := db.GetDB()
	if err != nil {
		return 0, false
	}
	var logChat int64
	if err := d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(modlogBucket))
		if b == nil {
			return nil
		}
		if v := b.Get([]byte(strconv.FormatInt(srcChat, 10))); v != nil {
			logChat, _ = strconv.ParseInt(string(v), 10, 64)
		}
		return nil
	}); err != nil {
		return 0, false
	}
	modlogMu.Lock()
	modlogCache[srcChat] = logChat
	modlogMu.Unlock()
	return logChat, logChat != 0
}

func unsetModlogChat(srcChat int64) error {
	d, err := db.GetDB()
	if err != nil {
		return err
	}
	err = d.Update(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(modlogBucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(strconv.FormatInt(srcChat, 10)))
	})
	if err != nil {
		return err
	}
	modlogMu.Lock()
	modlogCache[srcChat] = 0
	modlogMu.Unlock()
	return nil
}

func actionEmoji(action string) string {
	switch strings.ToLower(action) {
	case "ban", "tban", "sban", "dban":
		return "\U0001F6AB"
	case "unban":
		return "♻️"
	case "kick", "skick", "dkick", "punch":
		return "\U0001F462"
	case "mute", "tmute", "smute", "dmute", "restrict":
		return "\U0001F507"
	case "unmute", "unrestrict":
		return "\U0001F50A"
	case "warn", "twarn":
		return "⚠️"
	case "lock":
		return "\U0001F512"
	case "unlock":
		return "\U0001F513"
	case "purge", "del", "delete":
		return "\U0001F5D1️"
	case "pin":
		return "\U0001F4CC"
	case "unpin":
		return "\U0001F4CD"
	case "promote":
		return "⬆️"
	case "demote":
		return "⬇️"
	case "blacklist":
		return "\U0001F6D1"
	default:
		return "\U0001F4DD"
	}
}

// parseLogChatArg accepts "", a numeric chat ID (raw or -100 form) and returns the Bot API form.
func parseLogChatArg(arg string, here int64) (int64, bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return here, true
	}
	id, err := strconv.ParseInt(arg, 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return modules.NormChatID(id), true
}

func SetLogChatHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "change_info") {
		m.Reply("You need the <b>Change Group Info</b> admin right to configure the mod log.")
		return nil
	}

	arg, _ := modules.SplitFirstArg(modules.CommandArgs(m.Text()))
	target, ok := parseLogChatArg(arg, m.ChannelID())
	if !ok {
		m.Reply("Usage: <code>/setlogchat [chat_id]</code>\nExample: <code>/setlogchat -1001234567890</code>\nOmit the ID to log into this chat.")
		return nil
	}
	if target != m.ChannelID() && !modules.IsAnonAdmin(m) && !modules.IsChatAdmin(m.Client, target, m.SenderID()) {
		m.Reply("You must be an admin of the log chat too, and I must be a member there.")
		return nil
	}

	title := "this chat"
	if m.Channel != nil && m.Channel.Title != "" {
		title = m.Channel.Title
	} else if m.Chat != nil && m.Chat.Title != "" {
		title = m.Chat.Title
	}
	if _, err := m.Client.SendMessage(target, "Moderation log connected for <b>"+html.EscapeString(title)+"</b>."); err != nil {
		m.Reply(fmt.Sprintf("I can't post in chat <code>%d</code>. Add me there with permission to send messages, then try again.", target))
		return nil
	}

	if err := setModlogChat(m.ChatID(), target); err != nil {
		m.Reply("I couldn't save the log chat. Please try again.")
		return nil
	}
	m.Reply(fmt.Sprintf("Moderation log chat set to <code>%d</code>.", target))
	return nil
}

func UnsetLogChatHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "change_info") {
		m.Reply("You need the <b>Change Group Info</b> admin right to configure the mod log.")
		return nil
	}
	if _, ok := getModlogChat(m.ChatID()); !ok {
		m.Reply("No mod log chat is configured for this group.")
		return nil
	}
	if err := unsetModlogChat(m.ChatID()); err != nil {
		m.Reply("I couldn't clear the log chat. Please try again.")
		return nil
	}
	m.Reply("Moderation log disabled.")
	return nil
}

func LogStatusHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	logChat, ok := getModlogChat(m.ChatID())
	if !ok {
		m.Reply("Moderation log is <b>disabled</b> for this chat.\nUse <code>/setlogchat</code> to enable it.")
		return nil
	}
	m.Reply(fmt.Sprintf("Moderation log is <b>enabled</b>.\nLog chat: <code>%d</code>", modules.NormChatID(logChat)))
	return nil
}

// LogModerationAction posts an entry to srcChat's log chat. srcChat is the m.ChatID() key; actor, target
// and reason are plain text and get escaped here.
func LogModerationAction(srcChat int64, action, actor, target, reason string) {
	if modules.Client == nil {
		return
	}
	logChat, ok := getModlogChat(srcChat)
	if !ok {
		return
	}
	text := formatModlogEntry(srcChat, action, html.EscapeString(actor), html.EscapeString(target), reason)
	go func() {
		_, _ = modules.Client.SendMessage(modules.NormChatID(logChat), text)
	}()
}

// formatModlogEntry expects actor and target to be HTML already; reason is escaped here.
func formatModlogEntry(srcChat int64, action, actor, target, reason string) string {
	var sb strings.Builder
	sb.WriteString(actionEmoji(action))
	sb.WriteString(" <b>")
	sb.WriteString(html.EscapeString(strings.ToUpper(action)))
	sb.WriteString("</b>\n<b>Chat:</b> <code>")
	sb.WriteString(strconv.FormatInt(srcChat, 10))
	sb.WriteString("</code>\n")
	if strings.TrimSpace(actor) != "" {
		sb.WriteString("<b>By:</b> " + actor + "\n")
	}
	if strings.TrimSpace(target) != "" {
		sb.WriteString("<b>User:</b> " + target + "\n")
	}
	if strings.TrimSpace(reason) != "" {
		sb.WriteString("<b>Details:</b> <i>" + html.EscapeString(reason) + "</i>\n")
	}
	sb.WriteString("<b>Time:</b> <code>" + time.Now().UTC().Format("2006-01-02 15:04:05 UTC") + "</code>")
	return sb.String()
}

// classifyParticipantChange maps a participant transition to a log action, or "" if not worth logging.
func classifyParticipantChange(prev, cur tg.ChannelParticipant, now time.Time) (string, string) {
	if nb, ok := cur.(*tg.ChannelParticipantBanned); ok && nb.BannedRights != nil {
		r := nb.BannedRights
		if r.ViewMessages {
			if r.UntilDate != 0 && time.Unix(int64(r.UntilDate), 0).Sub(now) <= kickBanWindow {
				return "kick", ""
			}
			if r.UntilDate != 0 {
				return "tban", "until " + time.Unix(int64(r.UntilDate), 0).UTC().Format("2006-01-02 15:04 UTC")
			}
			return "ban", ""
		}
		if r.UntilDate != 0 {
			return "tmute", "until " + time.Unix(int64(r.UntilDate), 0).UTC().Format("2006-01-02 15:04 UTC")
		}
		return "restrict", ""
	}
	if ob, ok := prev.(*tg.ChannelParticipantBanned); ok && ob.BannedRights != nil {
		if ob.BannedRights.ViewMessages {
			return "unban", ""
		}
		return "unmute", ""
	}
	_, oldAdmin := prev.(*tg.ChannelParticipantAdmin)
	_, newAdmin := cur.(*tg.ChannelParticipantAdmin)
	switch {
	case newAdmin && !oldAdmin:
		return "promote", ""
	case oldAdmin && !newAdmin:
		return "demote", ""
	}
	if prev != nil && cur == nil {
		if _, isObj := prev.(*tg.ChannelParticipantObj); isObj {
			return "kick", ""
		}
	}
	if _, left := cur.(*tg.ChannelParticipantLeft); left && prev != nil {
		return "kick", ""
	}
	return "", ""
}

func ModlogParticipantHandler(p *tg.ParticipantUpdate) error {
	if p == nil || p.Channel == nil || p.User == nil || p.Actor == nil {
		return nil
	}
	if p.Actor.ID == p.User.ID {
		return nil
	}
	logChat, ok := getModlogChat(p.ChatID())
	if !ok {
		return nil
	}
	action, details := classifyParticipantChange(p.Old, p.New, time.Now())
	if action == "" {
		return nil
	}
	key := strconv.FormatInt(p.ChatID(), 10) + ":" + strconv.FormatInt(p.User.ID, 10)
	modlogKicksMu.Lock()
	for k, t := range modlogKicks {
		if time.Since(t) > time.Minute {
			delete(modlogKicks, k)
		}
	}
	_, recentKick := modlogKicks[key]
	if action == "kick" {
		modlogKicks[key] = time.Now()
	}
	modlogKicksMu.Unlock()
	// A kick is a ban immediately followed by an unban; the unban half is noise.
	if action == "unban" && recentKick {
		return nil
	}
	if action == "promote" || action == "demote" {
		modules.InvalidateChatAdmins(p.ChannelID())
	}

	actor := modules.UserMention(p.Actor.ID, modules.UserDisplayName(p.Actor))
	target := modules.UserMention(p.User.ID, modules.UserDisplayName(p.User)) + fmt.Sprintf(" (<code>%d</code>)", p.User.ID)
	text := formatModlogEntry(p.ChatID(), action, actor, target, details)
	if p.Channel.Title != "" {
		text = strings.Replace(text, "<b>Chat:</b> <code>", "<b>Chat:</b> "+html.EscapeString(p.Channel.Title)+" <code>", 1)
	}
	_, _ = p.Client.SendMessage(modules.NormChatID(logChat), text)
	return nil
}

func registerModlogHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:setlogchat", SetLogChatHandler)
	modules.OnCommand(c, "cmd:unsetlogchat", UnsetLogChatHandler)
	modules.OnCommand(c, "cmd:logstatus", LogStatusHandler)
	c.On(tg.OnParticipant, ModlogParticipantHandler)
}

func init() {
	modules.QueueHandlerRegistration(registerModlogHandlers)

	modules.Mods.AddModule("ModLog", `<b>Moderation Log</b>

Sends a log entry to a chat of your choice whenever someone is banned, temp-banned, kicked, muted/restricted, unbanned, unmuted, promoted or demoted in this group, including who did it. Actions done by any admin or bot are logged, not only mine.

<b>Commands:</b>
 - <code>/setlogchat</code> - Log into this chat
 - <code>/setlogchat &lt;chat_id&gt;</code> - Log into another group or channel
 - <code>/unsetlogchat</code> - Disable the moderation log
 - <code>/logstatus</code> - Show whether logging is on and where entries go

<b>Example:</b>
 <code>/setlogchat -1001234567890</code>

<b>Notes:</b>
 - You need the Change Group Info right here, and must be an admin of the log chat.
 - I must be a member of the log chat and able to post there; I send a test message when you set it.
 - Supergroups only, and I must be an admin to receive member events.`)
}
