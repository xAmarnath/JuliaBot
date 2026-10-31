package extras

import (
	"errors"
	"fmt"
	"html"
	"main/modules/db"
	"strconv"
	"strings"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	modules "main/modules"
)

const maxWarnReasonLen = 500

// ensureSenderRight replies with an explanation and returns false unless m is in a group and its sender holds right.
func ensureSenderRight(m *tg.NewMessage, right, label string) bool {
	if !modules.RequireGroup(m) {
		return false
	}
	if modules.SenderHasRight(m, right) {
		return true
	}
	if label == "" {
		m.Reply("Only admins can use this command.")
	} else {
		m.Reply("You need the <b>" + label + "</b> admin right to use this command.")
	}
	return false
}

func replyTargetError(m *tg.NewMessage, err error, usage string) {
	if errors.Is(err, modules.ErrNoTarget) {
		m.Reply(usage)
		return
	}
	m.Reply(modules.AdminFriendlyError(err, "find that user"))
}

func warnIsStale(w *db.Warn, s *db.WarnSettings, now time.Time) bool {
	if w.ExpiresAt > 0 && now.Unix() >= w.ExpiresAt {
		return true
	}
	return s.DecayDays > 0 && !w.Timestamp.IsZero() && now.Sub(w.Timestamp) > time.Duration(s.DecayDays)*24*time.Hour
}

func activeWarns(warns []*db.Warn, s *db.WarnSettings, now time.Time) []*db.Warn {
	out := make([]*db.Warn, 0, len(warns))
	for _, w := range warns {
		if !warnIsStale(w, s, now) {
			out = append(out, w)
		}
	}
	return out
}

// loadActiveWarns returns the user's live warns and prunes stale ones in the background.
func loadActiveWarns(chatID, userID int64, s *db.WarnSettings) ([]*db.Warn, error) {
	warns, err := db.GetWarns(chatID, userID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	active := activeWarns(warns, s, now)
	if len(active) != len(warns) {
		go db.RemoveWarns(chatID, userID, func(w *db.Warn) bool { return warnIsStale(w, s, now) })
	}
	return active, nil
}

func parseWarnAction(args string) (db.WarnAction, time.Duration, error) {
	name, rest := modules.SplitFirstArg(strings.ToLower(args))
	switch name {
	case "ban":
		return db.WarnActionBan, 0, nil
	case "kick":
		return db.WarnActionKick, 0, nil
	case "mute":
		return db.WarnActionMute, 0, nil
	case "tban", "tmute":
		first, _ := modules.SplitFirstArg(rest)
		d, err := modules.ParseTempDuration(first)
		if err != nil {
			return "", 0, err
		}
		if name == "tban" {
			return db.WarnActionTBan, d, nil
		}
		return db.WarnActionTMute, d, nil
	}
	return "", 0, modules.FriendlyError("Unknown action. Use one of: ban, kick, mute, tban &lt;duration&gt;, tmute &lt;duration&gt;.")
}

func warnActionText(s *db.WarnSettings) string {
	d := time.Duration(s.ActionDuration) * time.Second
	switch s.Action {
	case db.WarnActionKick:
		return "kick"
	case db.WarnActionMute:
		return "mute"
	case db.WarnActionTBan:
		return "temporary ban (" + formatDuration(d) + ")"
	case db.WarnActionTMute:
		return "temporary mute (" + formatDuration(d) + ")"
	}
	return "ban"
}

func applyWarnAction(c *tg.Client, chatID int64, t *modules.Target, s *db.WarnSettings) (string, error) {
	d := time.Duration(s.ActionDuration) * time.Second
	switch s.Action {
	case db.WarnActionKick:
		return "kicked", modules.KickMember(c, chatID, t.Peer)
	case db.WarnActionMute:
		return "muted", modules.MuteMember(c, chatID, t.Peer, 0)
	case db.WarnActionTMute:
		if d < modules.MinTempDuration {
			d = 24 * time.Hour
		}
		return "muted for " + formatDuration(d), modules.MuteMember(c, chatID, t.Peer, d)
	case db.WarnActionTBan:
		if d < modules.MinTempDuration {
			d = 24 * time.Hour
		}
		return "banned for " + formatDuration(d), modules.BanMember(c, chatID, t.Peer, d)
	}
	return "banned", modules.BanMember(c, chatID, t.Peer, 0)
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func resolveWarnTarget(m *tg.NewMessage, usage string) (*modules.Target, string, bool) {
	t, rest, err := modules.ResolveTarget(m)
	if err != nil {
		replyTargetError(m, err, usage)
		return nil, "", false
	}
	if t.IsChannel {
		m.Reply("Channels can't be warned. Use /ban instead.")
		return nil, "", false
	}
	if g := modules.TargetGuard(m, t, "warn"); g != "" {
		m.Reply(g)
		return nil, "", false
	}
	return t, rest, true
}

func issueWarn(m *tg.NewMessage, t *modules.Target, reason string, ttl time.Duration) {
	chatID := m.ChatID()
	reason = truncateRunes(strings.TrimSpace(reason), maxWarnReasonLen)
	warn := &db.Warn{Reason: reason, AdminID: m.SenderID(), Timestamp: time.Now()}
	if ttl > 0 {
		warn.ExpiresAt = time.Now().Add(ttl).Unix()
	}
	if _, err := db.AddWarn(chatID, t.ID, warn); err != nil {
		m.Reply("I couldn't save the warning. Please try again.")
		return
	}
	settings, _ := db.GetWarnSettings(chatID)
	warns, err := loadActiveWarns(chatID, t.ID, settings)
	if err != nil {
		warns = []*db.Warn{warn}
	}
	count := len(warns)

	reasonLine := ""
	if reason != "" {
		reasonLine = "\n<b>Reason:</b> " + html.EscapeString(reason)
	}

	if count >= settings.MaxWarns {
		if !modules.BotHasRight(m.Client, m.ChannelID(), "ban") {
			m.Reply(fmt.Sprintf("%s has reached %d/%d warnings, but I need the <b>Ban Users</b> right to act on it.%s", t.Mention(), count, settings.MaxWarns, reasonLine))
			return
		}
		did, err := applyWarnAction(m.Client, m.ChannelID(), t, settings)
		if err != nil {
			m.Reply(fmt.Sprintf("%s has reached %d/%d warnings.\n%s", t.Mention(), count, settings.MaxWarns, modules.AdminFriendlyError(err, "apply the warn action")))
			return
		}
		db.ResetWarns(chatID, t.ID)
		m.Reply(fmt.Sprintf("%s reached %d/%d warnings and was %s.%s", t.Mention(), count, settings.MaxWarns, did, reasonLine))
		LogModerationAction(chatID, "warn-"+string(settings.Action), senderName(m), t.Name, reason)
		return
	}

	expiry := ""
	if ttl > 0 {
		expiry = "\n<i>This warning expires in " + formatDuration(ttl) + ".</i>"
	}
	btn := tg.Button.Data("Remove warning", fmt.Sprintf("rmwarn_%d_w%s", t.ID, warn.ID))
	btn.Style = &tg.KeyboardButtonStyle{BgDanger: true}
	m.Reply(
		fmt.Sprintf("%s has been warned (%d/%d).%s%s", t.Mention(), count, settings.MaxWarns, reasonLine, expiry),
		&tg.SendOptions{ReplyMarkup: tg.NewKeyboard().AddRow(btn).Build()},
	)
	LogModerationAction(chatID, "warn", senderName(m), t.Name, reason)
}

func senderName(m *tg.NewMessage) string {
	if m.Sender != nil {
		return modules.UserDisplayName(m.Sender)
	}
	if modules.IsAnonAdmin(m) {
		return "Anonymous admin"
	}
	return ""
}

func WarnUserHandler(m *tg.NewMessage) error {
	if !ensureSenderRight(m, "ban", "Ban Users") {
		return nil
	}
	t, reason, ok := resolveWarnTarget(m, "<b>Usage:</b> <code>/warn @user [reason]</code> or reply to a message with <code>/warn [reason]</code>")
	if !ok {
		return nil
	}
	issueWarn(m, t, reason, 0)
	return nil
}

func TemporaryWarnHandler(m *tg.NewMessage) error {
	if !ensureSenderRight(m, "ban", "Ban Users") {
		return nil
	}
	usage := "<b>Usage:</b> <code>/twarn @user &lt;duration&gt; [reason]</code> or reply with <code>/twarn &lt;duration&gt; [reason]</code>\n<b>Example:</b> <code>/twarn @user 7d spam</code>"
	t, rest, ok := resolveWarnTarget(m, usage)
	if !ok {
		return nil
	}
	durStr, reason := modules.SplitFirstArg(rest)
	if durStr == "" {
		m.Reply(usage)
		return nil
	}
	d, err := modules.ParseTempDuration(durStr)
	if err != nil {
		m.Reply(modules.AdminFriendlyError(err, "parse the duration"))
		return nil
	}
	issueWarn(m, t, reason, d)
	return nil
}

func RemoveWarnCallback(c *tg.CallbackQuery) error {
	parts := strings.SplitN(strings.TrimPrefix(c.DataString(), "rmwarn_"), "_", 2)
	if len(parts) != 2 {
		c.Answer("Invalid button.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		c.Answer("Invalid button.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	if !modules.CallbackHasRight(c, "ban") {
		c.Answer("Only admins with the Ban Users right can remove warnings.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	chatID := c.ChatID
	var removed bool
	if id, ok := strings.CutPrefix(parts[1], "w"); ok {
		removed, err = db.RemoveWarnByID(chatID, userID, id)
	} else {
		removed, err = removeLastWarn(chatID, userID)
	}
	if err != nil {
		c.Answer("I couldn't remove the warning. Please try again.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	if !removed {
		c.Answer("That warning was already removed or has expired.", &tg.CallbackOptions{Alert: true})
		c.Edit("<i>This warning no longer exists.</i>")
		return nil
	}
	settings, _ := db.GetWarnSettings(chatID)
	warns, _ := loadActiveWarns(chatID, userID, settings)
	admin := "an admin"
	if c.Sender != nil {
		admin = modules.UserMention(c.Sender.ID, modules.UserDisplayName(c.Sender))
	}
	c.Answer("Warning removed.")
	c.Edit(fmt.Sprintf("Warning removed by %s. %s now has %d/%d warnings.", admin, modules.UserMention(userID, ""), len(warns), settings.MaxWarns))
	return nil
}

func removeLastWarn(chatID, userID int64) (bool, error) {
	settings, _ := db.GetWarnSettings(chatID)
	warns, err := loadActiveWarns(chatID, userID, settings)
	if err != nil || len(warns) == 0 {
		return false, err
	}
	last := warns[len(warns)-1]
	if last.ID != "" {
		return db.RemoveWarnByID(chatID, userID, last.ID)
	}
	// Legacy warns without IDs: match by timestamp and admin instead.
	n, err := db.RemoveWarns(chatID, userID, func(w *db.Warn) bool {
		return w.ID == "" && w.Timestamp.Equal(last.Timestamp) && w.AdminID == last.AdminID
	})
	return n > 0, err
}

func ListWarnsHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	t, _, err := modules.ResolveTarget(m)
	if errors.Is(err, modules.ErrNoTarget) {
		if modules.IsAnonAdmin(m) || m.SenderID() <= 0 {
			m.Reply("Reply to a user or give their @username to see their warnings.")
			return nil
		}
		t = &modules.Target{ID: m.SenderID(), User: m.Sender, Name: modules.UserDisplayName(m.Sender)}
	} else if err != nil {
		replyTargetError(m, err, "")
		return nil
	}

	settings, _ := db.GetWarnSettings(m.ChatID())
	warns, err := loadActiveWarns(m.ChatID(), t.ID, settings)
	if err != nil {
		m.Reply("I couldn't load warnings right now. Please try again.")
		return nil
	}
	if len(warns) == 0 {
		m.Reply(fmt.Sprintf("%s has no warnings.", t.Mention()))
		return nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>Warnings for</b> %s: <b>%d/%d</b>\n\n", t.Mention(), len(warns), settings.MaxWarns)
	names := map[int64]string{}
	for i, w := range warns {
		admin, ok := names[w.AdminID]
		if !ok {
			admin = "an admin"
			if u, err := m.Client.GetUser(w.AdminID); err == nil && u != nil {
				admin = modules.UserDisplayName(u)
			}
			names[w.AdminID] = admin
		}
		reason := w.Reason
		if reason == "" || reason == "No reason specified" {
			reason = "<i>no reason</i>"
		} else {
			reason = html.EscapeString(reason)
		}
		fmt.Fprintf(&sb, "%d. %s\n   <i>by %s on %s", i+1, reason, html.EscapeString(admin), w.Timestamp.Format("02 Jan 2006"))
		if w.ExpiresAt > 0 {
			fmt.Fprintf(&sb, ", expires in %s", formatDuration(time.Until(time.Unix(w.ExpiresAt, 0)).Round(time.Minute)))
		}
		sb.WriteString("</i>\n")
	}
	m.Reply(sb.String())
	return nil
}

func ResetWarnsHandler(m *tg.NewMessage) error {
	if !ensureSenderRight(m, "ban", "Ban Users") {
		return nil
	}
	t, _, err := modules.ResolveTarget(m)
	if err != nil {
		replyTargetError(m, err, "<b>Usage:</b> <code>/resetwarns @user</code> or reply to a user.")
		return nil
	}
	warns, _ := db.GetWarns(m.ChatID(), t.ID)
	if len(warns) == 0 {
		m.Reply(fmt.Sprintf("%s has no warnings to clear.", t.Mention()))
		return nil
	}
	if err := db.ResetWarns(m.ChatID(), t.ID); err != nil {
		m.Reply("I couldn't clear the warnings. Please try again.")
		return nil
	}
	m.Reply(fmt.Sprintf("Cleared all warnings for %s.", t.Mention()))
	LogModerationAction(m.ChatID(), "resetwarns", senderName(m), t.Name, "")
	return nil
}

func RemoveWarnHandler(m *tg.NewMessage) error {
	if !ensureSenderRight(m, "ban", "Ban Users") {
		return nil
	}
	t, _, err := modules.ResolveTarget(m)
	if err != nil {
		replyTargetError(m, err, "<b>Usage:</b> <code>/rmwarn @user</code> or reply to a user.")
		return nil
	}
	removed, err := removeLastWarn(m.ChatID(), t.ID)
	if err != nil {
		m.Reply("I couldn't remove the warning. Please try again.")
		return nil
	}
	if !removed {
		m.Reply(fmt.Sprintf("%s has no warnings to remove.", t.Mention()))
		return nil
	}
	settings, _ := db.GetWarnSettings(m.ChatID())
	warns, _ := loadActiveWarns(m.ChatID(), t.ID, settings)
	m.Reply(fmt.Sprintf("Removed the latest warning of %s. They now have %d/%d.", t.Mention(), len(warns), settings.MaxWarns))
	return nil
}

func SetWarnLimitHandler(m *tg.NewMessage) error {
	if !ensureSenderRight(m, "change_info", "Change Info") {
		return nil
	}
	arg, _ := modules.SplitFirstArg(modules.CommandArgs(m.Text()))
	settings, _ := db.GetWarnSettings(m.ChatID())
	if arg == "" {
		m.Reply(fmt.Sprintf("Current warning limit: <b>%d</b>\n\n<b>Usage:</b> <code>/setwarnlimit &lt;1-20&gt;</code>", settings.MaxWarns))
		return nil
	}
	limit, err := strconv.Atoi(arg)
	if err != nil || limit < 1 || limit > 20 {
		m.Reply("The warning limit must be a number between 1 and 20.")
		return nil
	}
	settings.MaxWarns = limit
	if err := db.SetWarnSettings(m.ChatID(), settings); err != nil {
		m.Reply("I couldn't save the warning limit. Please try again.")
		return nil
	}
	m.Reply(fmt.Sprintf("Warning limit set to <b>%d</b>.", limit))
	return nil
}

func SetWarnActionHandler(m *tg.NewMessage) error {
	if !ensureSenderRight(m, "change_info", "Change Info") {
		return nil
	}
	args := modules.CommandArgs(m.Text())
	settings, _ := db.GetWarnSettings(m.ChatID())
	if args == "" {
		m.Reply(fmt.Sprintf(`<b>Warn action</b>: %s (after %d warnings)

<b>Usage:</b> <code>/setwarnaction &lt;action&gt;</code>
 - <code>ban</code> - ban permanently
 - <code>kick</code> - remove, they can rejoin
 - <code>mute</code> - mute permanently
 - <code>tban 3d</code> - ban for a duration
 - <code>tmute 12h</code> - mute for a duration`, warnActionText(settings), settings.MaxWarns))
		return nil
	}
	action, d, err := parseWarnAction(args)
	if err != nil {
		m.Reply(modules.AdminFriendlyError(err, "set the warn action"))
		return nil
	}
	settings.Action = action
	settings.ActionDuration = int64(d / time.Second)
	if err := db.SetWarnSettings(m.ChatID(), settings); err != nil {
		m.Reply("I couldn't save the warn action. Please try again.")
		return nil
	}
	m.Reply("Warn action set to <b>" + warnActionText(settings) + "</b>.")
	return nil
}

func WarnDecayHandler(m *tg.NewMessage) error {
	if !ensureSenderRight(m, "change_info", "Change Info") {
		return nil
	}
	arg, _ := modules.SplitFirstArg(strings.ToLower(modules.CommandArgs(m.Text())))
	settings, _ := db.GetWarnSettings(m.ChatID())
	if arg == "" {
		state := "off"
		if settings.DecayDays > 0 {
			state = fmt.Sprintf("%d days", settings.DecayDays)
		}
		m.Reply(fmt.Sprintf("Warning expiry: <b>%s</b>\n\n<b>Usage:</b> <code>/warndecay &lt;days|off&gt;</code>", state))
		return nil
	}
	days := 0
	if arg != "off" && arg != "0" {
		n, err := strconv.Atoi(strings.TrimSuffix(arg, "d"))
		if err != nil || n < 1 || n > 365 {
			m.Reply("Give a number of days between 1 and 365, or <code>off</code>.")
			return nil
		}
		days = n
	}
	settings.DecayDays = days
	if err := db.SetWarnSettings(m.ChatID(), settings); err != nil {
		m.Reply("I couldn't save the setting. Please try again.")
		return nil
	}
	if days == 0 {
		m.Reply("Warnings no longer expire automatically.")
	} else {
		m.Reply(fmt.Sprintf("Warnings now expire <b>%d days</b> after they were given.", days))
	}
	return nil
}

func WarnSettingsHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	settings, _ := db.GetWarnSettings(m.ChatID())
	decay := "never"
	if settings.DecayDays > 0 {
		decay = fmt.Sprintf("after %d days", settings.DecayDays)
	}
	m.Reply(fmt.Sprintf(`<b>Warning settings</b>

<b>Limit:</b> %d warnings
<b>Action:</b> %s
<b>Warnings expire:</b> %s`, settings.MaxWarns, warnActionText(settings), decay))
	return nil
}

func registerWarnsHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:warn", WarnUserHandler)
	modules.OnCommand(c, "cmd:warns", ListWarnsHandler)
	modules.OnCommand(c, "cmd:rmwarn", RemoveWarnHandler)
	modules.OnCommand(c, "cmd:resetwarns", ResetWarnsHandler)
	modules.OnCommand(c, "cmd:setwarnlimit", SetWarnLimitHandler)
	modules.OnCommand(c, "cmd:setwarnaction", SetWarnActionHandler)
	modules.OnCommand(c, "cmd:setwarnmode", SetWarnActionHandler)
	modules.OnCommand(c, "cmd:warndecay", WarnDecayHandler)
	modules.OnCommand(c, "cmd:warnsettings", WarnSettingsHandler)
	modules.OnCommand(c, "cmd:twarn", TemporaryWarnHandler)
	c.On("callback:rmwarn_", RemoveWarnCallback)
}

func init() {
	modules.QueueHandlerRegistration(registerWarnsHandlers)

	modules.Mods.AddModule("Warns", `<b>Warnings</b>

Warn users; when they reach the limit the configured action is applied and their warnings reset. Admins, the owner and the bot can't be warned.

<b>Giving warnings</b> (Ban Users right):
 - <code>/warn @user [reason]</code> - or reply: <code>/warn [reason]</code>
 - <code>/twarn @user &lt;duration&gt; [reason]</code> - warning that expires by itself
   e.g. <code>/twarn @spammer 7d flooding</code>
 - <code>/rmwarn @user</code> - remove the latest warning
 - <code>/resetwarns @user</code> - clear all warnings
 The <b>Remove warning</b> button under a warn undoes exactly that warning.

<b>Viewing:</b>
 - <code>/warns</code> - your own warnings
 - <code>/warns @user</code> - someone's warnings (or reply)
 - <code>/warnsettings</code> - current limit, action and expiry

<b>Settings</b> (Change Info right):
 - <code>/setwarnlimit &lt;1-20&gt;</code> - warnings before action (default 3)
 - <code>/setwarnaction ban|kick|mute</code>
 - <code>/setwarnaction tban &lt;duration&gt;</code> / <code>tmute &lt;duration&gt;</code>
   e.g. <code>/setwarnaction tmute 12h</code> (<code>/setwarnmode</code> is an alias)
 - <code>/warndecay &lt;days|off&gt;</code> - warnings older than N days stop counting

Users can be given as reply, @username, numeric ID or text mention. Durations: <code>30m</code>, <code>2h</code>, <code>3d</code>, <code>1w</code>, <code>1h30m</code>.`)
}
