package modules

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	tg "github.com/xAmarnath/gogram/telegram"
)

// ------------------ Ban / kick / mute family ------------------

type restrictKind struct {
	action string
	past   string
	temp   bool
	guard  bool
	undo   bool
}

var restrictKinds = map[string]restrictKind{
	"ban":    {action: "ban", past: "banned", guard: true, undo: true},
	"tban":   {action: "ban", past: "banned", temp: true, guard: true, undo: true},
	"unban":  {action: "unban", past: "unbanned"},
	"kick":   {action: "kick", past: "kicked", guard: true},
	"mute":   {action: "mute", past: "muted", guard: true, undo: true},
	"tmute":  {action: "mute", past: "muted", temp: true, guard: true, undo: true},
	"unmute": {action: "unmute", past: "unmuted"},
}

const (
	modeNormal = iota
	modeSilent
	modeDelete
)

func restrictHandler(kind string, mode int) func(*tg.NewMessage) error {
	return func(m *tg.NewMessage) error {
		runRestrict(m, kind, mode)
		return nil
	}
}

func runRestrict(m *tg.NewMessage, kind string, mode int) {
	k := restrictKinds[kind]
	if !RequireGroup(m) {
		return
	}
	c, chatID := m.Client, m.ChannelID()
	reply := func(text string) {
		if mode == modeSilent {
			tempNotice(m, text, 6)
		} else {
			m.Reply(text)
		}
	}
	if mode == modeSilent {
		defer m.Delete()
	}

	anon := IsAnonAdmin(m)
	if !anon {
		if !UserHasRight(c, chatID, m.SenderID(), "ban") {
			reply("You need the <b>Ban Users</b> admin right to use this.")
			return
		}
		if mode == modeDelete && !UserHasRight(c, chatID, m.SenderID(), "delete") {
			reply("You need the <b>Delete Messages</b> admin right to use this.")
			return
		}
	}
	if !BotHasRight(c, chatID, "ban") {
		reply("I need the <b>Ban Users</b> admin right to do that.")
		return
	}
	if mode == modeDelete && !BotHasRight(c, chatID, "delete") {
		reply("I need the <b>Delete Messages</b> admin right to do that.")
		return
	}

	var (
		t       *Target
		rest    string
		err     error
		replyID int32
	)
	if mode == modeDelete {
		if !m.IsReply() {
			reply(adminUsage("d" + kind))
			return
		}
		r, rerr := m.GetReplyMessage()
		if rerr != nil || r == nil {
			reply("I couldn't read the replied message. It may have been deleted.")
			return
		}
		t, err = TargetFromMessage(m, r)
		rest, replyID = CommandArgs(m.Text()), r.ID
	} else {
		t, rest, err = ResolveTarget(m)
	}
	if err != nil {
		if errors.Is(err, ErrNoTarget) {
			reply(adminUsage(kind))
		} else {
			reply(AdminFriendlyError(err, k.action))
		}
		return
	}

	guard := lightGuard(c, t, k.action)
	if k.guard {
		guard = TargetGuard(m, t, k.action)
	}
	if guard != "" {
		reply(guard)
		return
	}

	var d time.Duration
	reason := rest
	if k.temp {
		durStr, after := SplitFirstArg(rest)
		if durStr == "" {
			reply(adminUsage(kind))
			return
		}
		if d, err = ParseTempDuration(durStr); err != nil {
			reply(AdminFriendlyError(err, k.action))
			return
		}
		reason = after
	}

	if anon {
		verifyKind := kind
		extra := ""
		if mode == modeDelete {
			verifyKind = "d" + kind
			extra = strconv.Itoa(int(replyID))
		} else if k.temp {
			extra = strconv.FormatInt(int64(d/time.Second), 10) + "s"
		}
		data := fmt.Sprintf("verify_op_%d_%s_%d", m.SenderID(), verifyKind, targetRef(t))
		if extra != "" {
			data += "_" + extra
		}
		kb := tg.NewKeyboard().AddRow(tg.Button.Data("Verify admin", data)).Build()
		m.Reply("You're posting anonymously. An admin with the <b>Ban Users</b> right must tap below to confirm.", &tg.SendOptions{ReplyMarkup: kb})
		return
	}

	if replyID != 0 {
		c.DeleteMessages(chatID, []int32{replyID})
	}
	text, err := applyRestriction(c, chatID, k, t, d, reason)
	if err != nil {
		reply(AdminFriendlyError(err, k.action))
		return
	}
	if mode == modeSilent {
		return
	}
	var opts []*tg.SendOptions
	if k.undo && isChannelID(NormChatID(chatID)) {
		label := "Unban"
		if k.action == "mute" {
			label = "Unmute"
		}
		btn := tg.Button.Data(label, fmt.Sprintf("undo_%s_%d_%d", kind, targetRef(t), m.SenderID()))
		opts = append(opts, &tg.SendOptions{ReplyMarkup: tg.NewKeyboard().AddRow(btn).Build()})
	}
	m.Reply(text, opts...)
}

// targetRef encodes channels in Bot API form so they can't be confused with user IDs.
func targetRef(t *Target) int64 {
	if t.IsChannel {
		return NormChatID(t.ID)
	}
	return t.ID
}

func lightGuard(c *tg.Client, t *Target, action string) string {
	if me := c.Me(); me != nil && !t.IsChannel && t.ID == me.ID {
		return "I can't " + action + " myself."
	}
	return ""
}

func applyRestriction(c *tg.Client, chatID int64, k restrictKind, t *Target, d time.Duration, reason string) (string, error) {
	var err error
	past := k.past
	switch k.action {
	case "ban":
		err = BanMember(c, chatID, t.Peer, d)
		if !isChannelID(NormChatID(chatID)) {
			past = "removed from the group"
		}
	case "unban":
		err = UnbanMember(c, chatID, t.Peer)
	case "kick":
		err = KickMember(c, chatID, t.Peer)
	case "mute":
		err = MuteMember(c, chatID, t.Peer, d)
	case "unmute":
		err = UnmuteMember(c, chatID, t.Peer)
	default:
		return "", FriendlyError("Unknown action.")
	}
	if err != nil {
		return "", err
	}
	text := t.Mention() + " has been " + past
	if d > 0 {
		text += " for " + formatAdminDuration(d)
	}
	text += "."
	if reason = strings.TrimSpace(reason); reason != "" {
		text += "\n<b>Reason:</b> " + html.EscapeString(truncateRunes(reason, 500))
	}
	return text, nil
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

// tempNotice sends (not replies, the command may already be deleted) a message that deletes itself.
func tempNotice(m *tg.NewMessage, text string, seconds int) {
	msg, err := m.Client.SendMessage(m.ChannelID(), text)
	if err != nil || msg == nil {
		return
	}
	go func(chatID int64, id int32) {
		time.Sleep(time.Duration(seconds) * time.Second)
		m.Client.DeleteMessages(chatID, []int32{id})
	}(m.ChannelID(), msg.ID)
}

func AdminVerifyCallback(cq *tg.CallbackQuery) error {
	parts := strings.Split(strings.TrimPrefix(cq.DataString(), "verify_op_"), "_")
	if len(parts) < 3 {
		cq.Answer("This button is no longer valid.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	issuer, err1 := strconv.ParseInt(parts[0], 10, 64)
	ref, err2 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil {
		cq.Answer("This button is no longer valid.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	kind := parts[1]
	deleteMode := false
	k, ok := restrictKinds[kind]
	if !ok && strings.HasPrefix(kind, "d") {
		k, ok = restrictKinds[kind[1:]]
		deleteMode = ok
	}
	if !ok {
		cq.Answer("This button is no longer valid.", &tg.CallbackOptions{Alert: true})
		return nil
	}

	c, chatID, clicker := cq.Client, cq.ChannelID(), cq.GetSenderID()
	anonIssuer := issuer == AnonBotID || issuer == rawChatID(chatID)
	if !anonIssuer && clicker != issuer {
		cq.Answer("This button isn't for you.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	if !UserHasRight(c, chatID, clicker, "ban") {
		cq.Answer("You need the Ban Users admin right.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	if deleteMode && !UserHasRight(c, chatID, clicker, "delete") {
		cq.Answer("You need the Delete Messages admin right.", &tg.CallbackOptions{Alert: true})
		return nil
	}

	t, err := targetFromID(c, ref)
	if err != nil {
		cq.Answer("I couldn't find that user anymore.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	guard := lightGuard(c, t, k.action)
	if k.guard {
		guard = guardFor(c, chatID, clicker, t, k.action)
	}
	if guard != "" {
		cq.Answer(guard, &tg.CallbackOptions{Alert: true})
		return nil
	}

	var d time.Duration
	if k.temp {
		if len(parts) < 4 {
			cq.Answer("This button is no longer valid.", &tg.CallbackOptions{Alert: true})
			return nil
		}
		if d, err = ParseTempDuration(parts[3]); err != nil {
			cq.Answer("Invalid duration.", &tg.CallbackOptions{Alert: true})
			return nil
		}
	}
	if deleteMode && len(parts) > 3 {
		if mid, err := strconv.Atoi(parts[3]); err == nil && mid > 0 {
			c.DeleteMessages(chatID, []int32{int32(mid)})
		}
	}

	text, err := applyRestriction(c, chatID, k, t, d, "")
	if err != nil {
		cq.Answer(stripTags(AdminFriendlyError(err, k.action)), &tg.CallbackOptions{Alert: true})
		return nil
	}
	cq.Answer("Done")
	cq.Edit(text)
	return nil
}

func AdminUndoCallback(cq *tg.CallbackQuery) error {
	parts := strings.Split(strings.TrimPrefix(cq.DataString(), "undo_"), "_")
	if len(parts) < 2 {
		cq.Answer("This button is no longer valid.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	ref, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		cq.Answer("This button is no longer valid.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	c, chatID := cq.Client, cq.ChannelID()
	if !CallbackHasRight(cq, "ban") {
		cq.Answer("You need the Ban Users admin right.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	t, err := targetFromID(c, ref)
	if err != nil {
		cq.Answer("I couldn't find that user anymore.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	var k restrictKind
	switch parts[0] {
	case "ban", "tban":
		k = restrictKinds["unban"]
	case "mute", "tmute":
		k = restrictKinds["unmute"]
	default:
		cq.Answer("This button is no longer valid.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	text, err := applyRestriction(c, chatID, k, t, 0, "")
	if err != nil {
		cq.Answer(stripTags(AdminFriendlyError(err, k.action)), &tg.CallbackOptions{Alert: true})
		return nil
	}
	if s := cq.Sender; s != nil {
		text += "\n<i>By " + UserMention(s.ID, UserDisplayName(s)) + "</i>"
	}
	cq.Answer("Done")
	cq.Edit(text)
	return nil
}

func stripTags(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return html.UnescapeString(b.String())
}

func KickMeHandle(m *tg.NewMessage) error {
	if !RequireGroup(m) {
		return nil
	}
	c, chatID := m.Client, m.ChannelID()
	if IsAnonAdmin(m) || IsChatAdmin(c, chatID, m.SenderID()) {
		m.Reply("Admins can't use /kickme.")
		return nil
	}
	if !BotHasRight(c, chatID, "ban") {
		m.Reply("I need the <b>Ban Users</b> admin right to do that.")
		return nil
	}
	peer, err := c.ResolvePeer(m.SenderID())
	if err != nil {
		m.Reply("I couldn't identify you.")
		return nil
	}
	if err := KickMember(c, chatID, peer); err != nil {
		m.Reply(AdminFriendlyError(err, "kick you"))
		return nil
	}
	m.Reply("Bye! You can rejoin any time.")
	return nil
}

// ------------------ Promote / demote / title ------------------

func intersectRights(a, b *tg.ChatAdminRights) *tg.ChatAdminRights {
	if a == nil || b == nil {
		return &tg.ChatAdminRights{}
	}
	return &tg.ChatAdminRights{
		ChangeInfo:     a.ChangeInfo && b.ChangeInfo,
		DeleteMessages: a.DeleteMessages && b.DeleteMessages,
		BanUsers:       a.BanUsers && b.BanUsers,
		InviteUsers:    a.InviteUsers && b.InviteUsers,
		PinMessages:    a.PinMessages && b.PinMessages,
		AddAdmins:      a.AddAdmins && b.AddAdmins,
		ManageCall:     a.ManageCall && b.ManageCall,
		ManageTopics:   a.ManageTopics && b.ManageTopics,
		PostStories:    a.PostStories && b.PostStories,
		EditStories:    a.EditStories && b.EditStories,
		DeleteStories:  a.DeleteStories && b.DeleteStories,
		Other:          a.Other && b.Other,
	}
}

func promoteRights(full bool) *tg.ChatAdminRights {
	r := &tg.ChatAdminRights{ChangeInfo: true, DeleteMessages: true, BanUsers: true, InviteUsers: true, PinMessages: true, ManageCall: true, Other: true}
	if full {
		r.AddAdmins, r.ManageTopics, r.PostStories, r.EditStories, r.DeleteStories = true, true, true, true, true
	}
	return r
}

// adminManagePrecheck validates caller and bot for promote/demote/title and returns the caller's admin info.
func adminManagePrecheck(m *tg.NewMessage) (*AdminInfo, bool) {
	if !RequireGroup(m) {
		return nil, false
	}
	if IsAnonAdmin(m) {
		m.Reply("Anonymous admins can't manage admins through me. Turn off <i>Remain anonymous</i> and try again.")
		return nil, false
	}
	sender := GetChatAdmin(m.Client, m.ChannelID(), m.SenderID())
	if !AdminRightAllowed(sender, "promote") {
		m.Reply("You need the <b>Add New Admins</b> right to do that.")
		return nil, false
	}
	if !BotHasRight(m.Client, m.ChannelID(), "promote") {
		m.Reply("I need the <b>Add New Admins</b> right to do that.")
		return nil, false
	}
	return sender, true
}

func resolveAdminTarget(m *tg.NewMessage, usage string) (*Target, string, bool) {
	t, rest, err := ResolveTarget(m)
	if err != nil {
		if errors.Is(err, ErrNoTarget) {
			m.Reply(adminUsage(usage))
		} else {
			m.Reply(AdminFriendlyError(err, usage))
		}
		return nil, "", false
	}
	if t.IsChannel {
		m.Reply("Only users can be admins.")
		return nil, "", false
	}
	if me := m.Client.Me(); me != nil && t.ID == me.ID {
		m.Reply("I can't change my own admin rights.")
		return nil, "", false
	}
	return t, rest, true
}

func validAdminTitle(m *tg.NewMessage, title string) bool {
	if utf8.RuneCountInString(title) > 16 {
		m.Reply("Admin titles can be at most 16 characters.")
		return false
	}
	return true
}

func promoteHandler(full bool) func(*tg.NewMessage) error {
	return func(m *tg.NewMessage) error {
		sender, ok := adminManagePrecheck(m)
		if !ok {
			return nil
		}
		t, title, ok := resolveAdminTarget(m, "promote")
		if !ok {
			return nil
		}
		c, chatID := m.Client, m.ChannelID()
		if a := GetChatAdmin(c, chatID, t.ID); a != nil && a.Creator {
			m.Reply("That's the chat owner; they already have every right.")
			return nil
		}
		title = strings.TrimSpace(title)
		if !validAdminTitle(m, title) {
			return nil
		}
		rights := promoteRights(full)
		if me := c.Me(); me != nil {
			if bot := GetChatAdmin(c, chatID, me.ID); bot != nil && !bot.Creator {
				rights = intersectRights(rights, bot.Rights)
			}
		}
		if !sender.Creator {
			rights = intersectRights(rights, sender.Rights)
		}
		_, err := c.EditAdmin(chatID, t.Peer, &tg.AdminOptions{IsAdmin: true, Rights: rights, Rank: title})
		InvalidateChatAdmins(chatID)
		if err != nil {
			m.Reply(AdminFriendlyError(err, "promote"))
			return nil
		}
		text := t.Mention() + " has been promoted"
		if full {
			text += " with full rights"
		}
		text += "."
		if title != "" && isChannelID(NormChatID(chatID)) {
			text += "\n<b>Title:</b> " + html.EscapeString(title)
		}
		m.Reply(text)
		return nil
	}
}

func DemoteUserHandle(m *tg.NewMessage) error {
	if _, ok := adminManagePrecheck(m); !ok {
		return nil
	}
	t, _, ok := resolveAdminTarget(m, "demote")
	if !ok {
		return nil
	}
	c, chatID := m.Client, m.ChannelID()
	a := GetChatAdmin(c, chatID, t.ID)
	if a == nil {
		m.Reply(t.Mention() + " isn't an admin.")
		return nil
	}
	if a.Creator {
		m.Reply("I can't demote the chat owner.")
		return nil
	}
	_, err := c.EditAdmin(chatID, t.Peer, &tg.AdminOptions{IsAdmin: false})
	InvalidateChatAdmins(chatID)
	if err != nil {
		m.Reply(AdminFriendlyError(err, "demote"))
		return nil
	}
	m.Reply(t.Mention() + " has been demoted.")
	return nil
}

func AdminTitleHandle(m *tg.NewMessage) error {
	if _, ok := adminManagePrecheck(m); !ok {
		return nil
	}
	c, chatID := m.Client, m.ChannelID()
	if !isChannelID(NormChatID(chatID)) {
		m.Reply("Admin titles are only available in supergroups.")
		return nil
	}
	t, title, ok := resolveAdminTarget(m, "title")
	if !ok {
		return nil
	}
	title = strings.TrimSpace(title)
	if !validAdminTitle(m, title) {
		return nil
	}
	a := GetChatAdmin(c, chatID, t.ID)
	if a == nil {
		m.Reply(t.Mention() + " isn't an admin. Promote them first with /promote.")
		return nil
	}
	if a.Creator {
		m.Reply("Only the owner can change their own title.")
		return nil
	}
	rights := a.Rights
	if rights == nil {
		rights = &tg.ChatAdminRights{}
	}
	_, err := c.EditAdmin(chatID, t.Peer, &tg.AdminOptions{IsAdmin: true, Rights: rights, Rank: title})
	InvalidateChatAdmins(chatID)
	if err != nil {
		m.Reply(AdminFriendlyError(err, "set the title"))
		return nil
	}
	if title == "" {
		m.Reply("Cleared the title of " + t.Mention() + ".")
	} else {
		m.Reply("Set the title of " + t.Mention() + " to <b>" + html.EscapeString(title) + "</b>.")
	}
	return nil
}

// ------------------ Admin list / zombies ------------------

func AdminListHandle(m *tg.NewMessage) error {
	if !RequireGroup(m) {
		return nil
	}
	c := m.Client
	admins, order, err := GetChatAdmins(c, m.ChannelID())
	if err != nil {
		m.Reply(AdminFriendlyError(err, "fetch the admin list"))
		return nil
	}
	var owner string
	var humans, bots []string
	hidden := 0
	for _, id := range order {
		a := admins[id]
		u := a.User
		if u == nil {
			u, _ = c.GetUser(id)
		}
		if a.Rights != nil && a.Rights.Anonymous {
			hidden++
			continue
		}
		line := UserMention(id, UserDisplayName(u))
		if a.Rank != "" {
			line += " · <i>" + html.EscapeString(a.Rank) + "</i>"
		}
		switch {
		case a.Creator:
			owner = line
		case u != nil && u.Bot:
			bots = append(bots, line)
		default:
			humans = append(humans, line)
		}
	}
	var b strings.Builder
	b.WriteString("<b>Admins</b>\n")
	if owner != "" {
		b.WriteString("\n<b>Owner:</b> " + owner + "\n")
	}
	if len(humans) > 0 {
		b.WriteString("\n")
		for _, l := range humans {
			b.WriteString("• " + l + "\n")
		}
	}
	if len(bots) > 0 {
		b.WriteString("\n<b>Bots:</b>\n")
		for _, l := range bots {
			b.WriteString("• " + l + "\n")
		}
	}
	if hidden > 0 {
		fmt.Fprintf(&b, "\n<i>%d anonymous admin(s) hidden.</i>", hidden)
	}
	m.Reply(strings.TrimSpace(b.String()))
	return nil
}

func AdminCacheHandle(m *tg.NewMessage) error {
	if !RequireGroup(m) {
		return nil
	}
	if !SenderIsAdmin(m) {
		m.Reply("Only admins can refresh the admin list.")
		return nil
	}
	InvalidateChatAdmins(m.ChannelID())
	m.Reply("Admin list refreshed.")
	return nil
}

var zombieRuns sync.Map

func ZombiesHandle(m *tg.NewMessage) error {
	if !RequireGroup(m) {
		return nil
	}
	c, chatID := m.Client, m.ChannelID()
	clean := strings.EqualFold(CommandArgs(m.Text()), "clean")
	right := ""
	if clean {
		right = "ban"
	}
	if !SenderHasRight(m, right) {
		if clean {
			m.Reply("You need the <b>Ban Users</b> admin right to remove deleted accounts.")
		} else {
			m.Reply("Only admins can use this.")
		}
		return nil
	}
	if clean && !BotHasRight(c, chatID, "ban") {
		m.Reply("I need the <b>Ban Users</b> admin right to remove deleted accounts.")
		return nil
	}
	if _, busy := zombieRuns.LoadOrStore(chatID, true); busy {
		m.Reply("I'm already scanning this chat. Please wait.")
		return nil
	}
	defer zombieRuns.Delete(chatID)

	status, _ := m.Reply("Scanning members for deleted accounts…")
	edit := func(text string) {
		if status != nil {
			status.Edit(text)
		} else {
			m.Reply(text)
		}
	}
	zombies, err := findDeletedMembers(c, chatID)
	if err != nil && len(zombies) == 0 {
		edit(AdminFriendlyError(err, "scan members"))
		return nil
	}
	if len(zombies) == 0 {
		edit("No deleted accounts found. This group is clean.")
		return nil
	}
	if !clean {
		edit(fmt.Sprintf("Found <b>%d</b> deleted account(s). Use <code>/zombies clean</code> to remove them.", len(zombies)))
		return nil
	}

	const maxClean = 500
	removed, failed, skipped := 0, 0, 0
	for i, peer := range zombies {
		if i >= maxClean {
			skipped = len(zombies) - maxClean
			break
		}
		if IsChatAdmin(c, chatID, peer.UserID) {
			failed++
			continue
		}
		if err := KickMember(c, chatID, peer); err != nil {
			failed++
		} else {
			removed++
		}
		time.Sleep(300 * time.Millisecond)
	}
	text := fmt.Sprintf("Removed <b>%d</b> deleted account(s).", removed)
	if failed > 0 {
		text += fmt.Sprintf(" %d could not be removed.", failed)
	}
	if skipped > 0 {
		text += fmt.Sprintf(" %d more remain; run the command again.", skipped)
	}
	edit(text)
	return nil
}

func findDeletedMembers(c *tg.Client, chatID int64) ([]*tg.InputPeerUser, error) {
	var out []*tg.InputPeerUser
	if !isChannelID(NormChatID(chatID)) {
		full, err := c.MessagesGetFullChat(rawChatID(chatID))
		if err != nil {
			return nil, err
		}
		for _, u := range usersByID(full.Users) {
			if u.Deleted {
				out = append(out, &tg.InputPeerUser{UserID: u.ID, AccessHash: u.AccessHash})
			}
		}
		return out, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	members, errs := c.IterChatMembers(chatID, &tg.ParticipantOptions{Ctx: ctx, Filter: &tg.ChannelParticipantsRecent{}, SleepThresholdMs: 300})
	for p := range members {
		if p != nil && p.User != nil && p.User.Deleted {
			out = append(out, &tg.InputPeerUser{UserID: p.User.ID, AccessHash: p.User.AccessHash})
		}
	}
	return out, <-errs
}

// ------------------ Chat info ------------------

func SetChatTitleHandle(m *tg.NewMessage) error {
	if !chatInfoPrecheck(m) {
		return nil
	}
	title := strings.TrimSpace(CommandArgs(m.Text()))
	if title == "" {
		m.Reply("Usage: <code>/settitle New group title</code>")
		return nil
	}
	if utf8.RuneCountInString(title) > 128 {
		m.Reply("Group titles can be at most 128 characters.")
		return nil
	}
	if _, err := m.Client.EditTitle(m.ChannelID(), title); err != nil {
		m.Reply(AdminFriendlyError(err, "change the title"))
		return nil
	}
	m.Reply("Group title updated.")
	return nil
}

func SetChatDescHandle(m *tg.NewMessage) error {
	if !chatInfoPrecheck(m) {
		return nil
	}
	about := strings.TrimSpace(CommandArgs(m.Text()))
	if about == "" && m.IsReply() {
		if r, err := m.GetReplyMessage(); err == nil && r != nil {
			about = strings.TrimSpace(r.Text())
		}
	}
	if about == "" {
		m.Reply("Usage: <code>/setdesc New description</code> (or reply to a message). Use <code>/setdesc clear</code> to remove it.")
		return nil
	}
	if strings.EqualFold(about, "clear") {
		about = ""
	}
	if utf8.RuneCountInString(about) > 255 {
		m.Reply("Descriptions can be at most 255 characters.")
		return nil
	}
	peer, err := m.Client.ResolvePeer(m.ChannelID())
	if err == nil {
		_, err = m.Client.MessagesEditChatAbout(peer, about)
	}
	if err != nil {
		m.Reply(AdminFriendlyError(err, "change the description"))
		return nil
	}
	if about == "" {
		m.Reply("Group description cleared.")
	} else {
		m.Reply("Group description updated.")
	}
	return nil
}

func chatInfoPrecheck(m *tg.NewMessage) bool {
	if !RequireGroup(m) {
		return false
	}
	if !SenderHasRight(m, "info") {
		m.Reply("You need the <b>Change Group Info</b> admin right to do that.")
		return false
	}
	if !BotHasRight(m.Client, m.ChannelID(), "info") {
		m.Reply("I need the <b>Change Group Info</b> admin right to do that.")
		return false
	}
	return true
}

// ------------------ Messages: del / purge / pin ------------------

func deletePrecheck(m *tg.NewMessage) bool {
	if !RequireGroup(m) {
		return false
	}
	if !SenderHasRight(m, "delete") {
		m.Reply("You need the <b>Delete Messages</b> admin right to do that.")
		return false
	}
	if !BotHasRight(m.Client, m.ChannelID(), "delete") {
		m.Reply("I need the <b>Delete Messages</b> admin right to do that.")
		return false
	}
	return true
}

func DeleteMessageHandle(m *tg.NewMessage) error {
	if !deletePrecheck(m) {
		return nil
	}
	if !m.IsReply() || m.ReplyToMsgID() == 0 {
		m.Reply(adminUsage("del"))
		return nil
	}
	if _, err := m.Client.DeleteMessages(m.ChannelID(), []int32{m.ReplyToMsgID(), m.ID}); err != nil {
		m.Reply(AdminFriendlyError(err, "delete that message"))
	}
	return nil
}

const maxPurge = 5000

func PurgeMessagesHandle(m *tg.NewMessage) error {
	if !deletePrecheck(m) {
		return nil
	}
	chatID := m.ChannelID()
	// Basic-group message IDs are shared across all of the bot's chats, so a range delete could hit other chats.
	if !isChannelID(NormChatID(chatID)) {
		m.Reply("Purge only works in supergroups. Use /del on individual messages here.")
		return nil
	}
	if !m.IsReply() || m.ReplyToMsgID() == 0 {
		m.Reply(adminUsage("purge"))
		return nil
	}
	start, end := m.ReplyToMsgID(), m.ID
	if start >= end {
		m.Reply("The replied message must be older than your command.")
		return nil
	}
	capped := false
	if end-start+1 > maxPurge {
		start, capped = end-maxPurge+1, true
	}

	status := NewStatus(m, "Purging messages…")
	deleted := 0
	var firstErr error
	for from := start; from <= end; from += 100 {
		to := min(from+99, end)
		ids := make([]int32, 0, to-from+1)
		for id := from; id <= to; id++ {
			ids = append(ids, id)
		}
		res, err := m.Client.DeleteMessages(chatID, ids)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if strings.Contains(err.Error(), "CHAT_ADMIN_REQUIRED") || strings.Contains(err.Error(), "FLOOD_WAIT") {
				break
			}
			continue
		}
		if res != nil {
			deleted += int(res.PtsCount)
		}
		if to < end {
			time.Sleep(300 * time.Millisecond)
		}
	}
	if deleted == 0 && firstErr != nil {
		status.Done()
		tempNotice(m, AdminFriendlyError(firstErr, "purge"), 8)
		return nil
	}
	text := fmt.Sprintf("Purged %d message(s).", deleted)
	if capped {
		text += fmt.Sprintf(" (Limited to the latest %d.)", maxPurge)
	}
	status.Done()
	tempNotice(m, text, 5)
	return nil
}

func pinPrecheck(m *tg.NewMessage) bool {
	if !RequireGroup(m) {
		return false
	}
	if !SenderHasRight(m, "pin") {
		m.Reply("You need the <b>Pin Messages</b> admin right to do that.")
		return false
	}
	if !BotHasRight(m.Client, m.ChannelID(), "pin") {
		m.Reply("I need the <b>Pin Messages</b> admin right to do that.")
		return false
	}
	return true
}

func PinMessageHandle(m *tg.NewMessage) error {
	if !pinPrecheck(m) {
		return nil
	}
	if !m.IsReply() || m.ReplyToMsgID() == 0 {
		m.Reply(adminUsage("pin"))
		return nil
	}
	arg := strings.ToLower(CommandArgs(m.Text()))
	loud := arg == "loud" || arg == "notify"
	if _, err := m.Client.PinMessage(m.ChannelID(), m.ReplyToMsgID(), &tg.PinOptions{Silent: !loud}); err != nil {
		m.Reply(AdminFriendlyError(err, "pin that message"))
		return nil
	}
	if loud {
		m.Reply("Pinned and notified members.")
	} else {
		m.Reply("Pinned.")
	}
	return nil
}

func UnpinMessageHandle(m *tg.NewMessage) error {
	if !pinPrecheck(m) {
		return nil
	}
	if strings.EqualFold(CommandArgs(m.Text()), "all") {
		return askUnpinAll(m)
	}
	c, chatID := m.Client, m.ChannelID()
	msgID := int32(0)
	if m.IsReply() {
		msgID = m.ReplyToMsgID()
	} else {
		pinned, err := c.GetPinnedMessage(chatID)
		if err != nil || pinned == nil {
			m.Reply("There's no pinned message here.")
			return nil
		}
		msgID = pinned.ID
	}
	if _, err := c.UnpinMessage(chatID, msgID); err != nil {
		m.Reply(AdminFriendlyError(err, "unpin that message"))
		return nil
	}
	m.Reply("Unpinned.")
	return nil
}

func UnpinAllHandle(m *tg.NewMessage) error {
	if !pinPrecheck(m) {
		return nil
	}
	return askUnpinAll(m)
}

func askUnpinAll(m *tg.NewMessage) error {
	kb := tg.NewKeyboard().AddRow(
		tg.Button.Data("Yes, unpin all", "unpinall_yes"),
		tg.Button.Data("Cancel", "unpinall_no"),
	).Build()
	m.Reply("Unpin <b>all</b> pinned messages in this chat?", &tg.SendOptions{ReplyMarkup: kb})
	return nil
}

func UnpinAllCallback(cq *tg.CallbackQuery) error {
	if !CallbackHasRight(cq, "pin") {
		cq.Answer("You need the Pin Messages admin right.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	if cq.DataString() != "unpinall_yes" {
		cq.Answer("Cancelled")
		cq.Edit("Cancelled. Nothing was unpinned.")
		return nil
	}
	peer, err := cq.Client.ResolvePeer(cq.ChannelID())
	if err == nil {
		_, err = cq.Client.MessagesUnpinAllMessages(peer, 0, nil)
	}
	if err != nil {
		cq.Answer(stripTags(AdminFriendlyError(err, "unpin messages")), &tg.CallbackOptions{Alert: true})
		return nil
	}
	cq.Answer("Done")
	cq.Edit("All pinned messages have been unpinned.")
	return nil
}

// ------------------ /id ------------------

func peerTypeName(p tg.Peer) string {
	switch p.(type) {
	case *tg.PeerChannel:
		return "Channel"
	case *tg.PeerUser:
		return "User"
	case *tg.PeerChat:
		return "Chat"
	}
	return "Hidden"
}

func IDHandle(m *tg.NewMessage) error {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>User:</b> <code>%d</code>\n<b>Chat:</b> <code>%d</code>", m.SenderID(), m.ChannelID())

	if m.Message != nil && m.Message.FwdFrom != nil {
		if id := m.Client.GetPeerID(m.Message.FwdFrom.FromID); id != 0 {
			fmt.Fprintf(&b, "\n\n<b>Forwarded From:</b> <code>%d</code> (%s)", id, peerTypeName(m.Message.FwdFrom.FromID))
		}
	}

	if CommandArgs(m.Text()) != "" {
		if t, _, err := ResolveTarget(m); err == nil && t != nil {
			fmt.Fprintf(&b, "\n\n%s: <code>%d</code>", t.Mention(), targetRef(t))
		}
	} else if m.IsReply() {
		if r, err := m.GetReplyMessage(); err == nil && r != nil {
			fmt.Fprintf(&b, "\n\n<b>Reply To:</b> <code>%d</code>\n<b>Reply MsgID:</b> <code>%d</code>", r.SenderID(), r.ID)
			if r.IsMedia() && r.File != nil && r.File.FileID != "" {
				fmt.Fprintf(&b, "\n<b>Reply FileID:</b> <code>%s</code>", html.EscapeString(r.File.FileID))
			}
			if r.Message != nil && r.Message.FwdFrom != nil {
				if id := m.Client.GetPeerID(r.Message.FwdFrom.FromID); id != 0 {
					fmt.Fprintf(&b, "\n<b>Reply Fwd:</b> <code>%d</code> (%s)", id, peerTypeName(r.Message.FwdFrom.FromID))
				}
			}
		}
	}
	m.Reply(b.String())
	return nil
}

// ------------------ Misc ------------------

func adminCacheParticipantWatcher(pu *tg.ParticipantUpdate) error {
	isAdmin := func(p tg.ChannelParticipant) bool {
		switch p.(type) {
		case *tg.ChannelParticipantAdmin, *tg.ChannelParticipantCreator:
			return true
		}
		return false
	}
	if pu != nil && pu.Channel != nil && (isAdmin(pu.Old) || isAdmin(pu.New)) {
		InvalidateChatAdmins(pu.ChannelID())
	}
	return nil
}

func adminUsage(action string) string {
	switch action {
	case "promote", "fullpromote":
		return "Usage: reply to a user or give their @username/ID, optionally followed by a title (max 16 chars).\nExample: <code>/promote @user Moderator</code>"
	case "demote":
		return "Usage: reply to an admin or give their @username/ID.\nExample: <code>/demote @user</code>"
	case "title":
		return "Usage: <code>/title @user New Title</code> (or reply). Leave the title empty to clear it."
	case "ban", "unban", "kick", "mute", "unmute":
		return fmt.Sprintf("Usage: reply to a user or give their @username/ID, optionally followed by a reason.\nExample: <code>/%s @user spamming</code>", action)
	case "tban", "tmute":
		return fmt.Sprintf("Usage: reply to a user or give their @username/ID, then a duration (1m, 2h, 3d, 1w) and an optional reason.\nExample: <code>/%s @user 2h flooding</code>", action)
	case "dban", "dmute", "dkick":
		return fmt.Sprintf("Usage: reply to the offending message with <code>/%s [reason]</code>. I'll delete it and %s the sender.", action, action[1:])
	case "del":
		return "Reply to the message you want to delete with /del."
	case "purge":
		return "Reply to the oldest message you want removed with /purge. Everything from there up to your command is deleted."
	case "pin":
		return "Reply to the message you want to pin. Add <code>loud</code> to notify members: <code>/pin loud</code>"
	}
	return "Reply to a user's message or give their @username/ID."
}

func formatAdminDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	units := []struct {
		d    time.Duration
		name string
	}{{7 * 24 * time.Hour, "week"}, {24 * time.Hour, "day"}, {time.Hour, "hour"}, {time.Minute, "minute"}, {time.Second, "second"}}
	var parts []string
	for _, u := range units {
		if n := int(d / u.d); n > 0 {
			d -= time.Duration(n) * u.d
			s := fmt.Sprintf("%d %s", n, u.name)
			if n != 1 {
				s += "s"
			}
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

func AdminFriendlyError(err error, action string) string {
	return parseAdminError(err, action)
}

func ReplyTemp(m *tg.NewMessage, text string, seconds int) {
	msg, err := m.Reply(text)
	if err != nil || msg == nil {
		tempNotice(m, text, seconds)
		return
	}
	if seconds <= 0 {
		return
	}
	go func(chatID int64, msgID int32, delay int) {
		time.Sleep(time.Duration(delay) * time.Second)
		m.Client.DeleteMessages(chatID, []int32{msgID})
	}(m.ChannelID(), msg.ID, seconds)
}

func init() {
	QueueHandlerRegistration(registerAdminHandlers)
	Mods.AddModule("Bans", `<b>Bans, Kicks &amp; Mutes</b>
Target a user by <b>replying</b> to their message, or with their <code>@username</code>, numeric ID or a text mention. Anything after the user is the reason or duration.

<b>Bans</b> (needs Ban Users)
/ban &lt;user&gt; [reason] — ban permanently
/tban &lt;user&gt; &lt;time&gt; [reason] — temporary ban
/sban &lt;user&gt; — silent ban (deletes your command, no reply)
/dban [reason] — reply only: delete the message and ban its sender
/unban &lt;user&gt; — lift a ban

<b>Kicks</b> (needs Ban Users) — the user can rejoin
/kick &lt;user&gt; [reason]
/skick &lt;user&gt; — silent kick
/dkick [reason] — reply only: delete the message and kick its sender
/kickme — remove yourself (non-admins)

<b>Mutes</b> (needs Ban Users, supergroups only)
/mute &lt;user&gt; [reason]
/tmute &lt;user&gt; &lt;time&gt; [reason]
/smute &lt;user&gt; — silent mute
/dmute [reason] — reply only: delete the message and mute its sender
/unmute &lt;user&gt;

<b>Time format:</b> <code>30m</code>, <code>2h</code>, <code>3d</code>, <code>1w</code>, combined like <code>1h30m</code>. A bare number means minutes. Minimum 1 minute, maximum 366 days.
Examples: <code>/tban @spammer 3d ads</code>, <code>/tmute 2h</code> (as a reply)

<b>Notes</b>
• Admins and the owner can't be banned, kicked or muted.
• Anonymous admins get a confirmation button that an admin with Ban Users must press.
• Basic groups: /ban removes the user (no ban list); mutes and temp bans need a supergroup.
• Ban and mute replies include an Unban/Unmute button usable by any admin with Ban Users.`)

	Mods.AddModule("Admin", `<b>Admin</b>
Target a user by <b>replying</b> to their message, or with their <code>@username</code>, numeric ID or a text mention.

<b>Admins</b> (needs Add New Admins)
/promote &lt;user&gt; [title] — standard rights (info, delete, ban, invite, pin, calls)
/fullpromote &lt;user&gt; [title] — also add admins, topics and stories
/demote &lt;user&gt; — remove admin rights
/title &lt;user&gt; [title] — set or clear an admin's custom title (max 16 chars)
You can only grant rights that both you and I have.
/admins — list admins (anonymous admins are hidden)
/admincache — refresh my cached admin list

<b>Messages</b>
/del — reply: delete that message (needs Delete Messages)
/purge — reply: delete everything from that message to your command (supergroups, max 5000)
/pin [loud] — reply: pin silently, or with <code>loud</code> to notify everyone
/unpin — reply: unpin that message; without a reply unpins the latest pin
/unpinall or /unpin all — unpin everything (asks to confirm)

<b>Group</b>
/settitle &lt;text&gt; — change the group title (needs Change Info)
/setdesc &lt;text&gt; — change the description; reply to use a message's text; <code>/setdesc clear</code> removes it
/zombies — count deleted accounts; <code>/zombies clean</code> removes them (needs Ban Users)
/id [user] — show user/chat IDs, or the replied message's details

Anonymous admins get a confirmation button that an admin with the needed right must press.`)
}

func registerAdminHandlers() {
	c := Client
	OnCommand(c, "cmd:rspot", RestartSpotify, tg.FromUsers(OwnerId))
	OnCommand(c, "cmd:rproxy", RestartProxy, tg.CustomFilter(FilterOwnerAndAuth))
	OnCommand(c, "cmd:restart", RestartHandle, tg.CustomFilter(FilterOwner))

	OnCommand(c, "cmd:promote", promoteHandler(false))
	OnCommand(c, "cmd:fullpromote", promoteHandler(true))
	OnCommand(c, "cmd:demote", DemoteUserHandle)
	OnCommand(c, "cmd:title", AdminTitleHandle)

	OnCommand(c, "cmd:ban", restrictHandler("ban", modeNormal))
	OnCommand(c, "cmd:tban", restrictHandler("tban", modeNormal))
	OnCommand(c, "cmd:sban", restrictHandler("ban", modeSilent))
	OnCommand(c, "cmd:dban", restrictHandler("ban", modeDelete))
	OnCommand(c, "cmd:unban", restrictHandler("unban", modeNormal))
	OnCommand(c, "cmd:kick", restrictHandler("kick", modeNormal))
	OnCommand(c, "cmd:skick", restrictHandler("kick", modeSilent))
	OnCommand(c, "cmd:dkick", restrictHandler("kick", modeDelete))
	OnCommand(c, "cmd:kickme", KickMeHandle)
	OnCommand(c, "cmd:mute", restrictHandler("mute", modeNormal))
	OnCommand(c, "cmd:tmute", restrictHandler("tmute", modeNormal))
	OnCommand(c, "cmd:smute", restrictHandler("mute", modeSilent))
	OnCommand(c, "cmd:dmute", restrictHandler("mute", modeDelete))
	OnCommand(c, "cmd:unmute", restrictHandler("unmute", modeNormal))
	c.On("callback:undo_", AdminUndoCallback)

	OnCommand(c, "cmd:admins", AdminListHandle)
	OnCommand(c, "cmd:adminlist", AdminListHandle)
	OnCommand(c, "cmd:staff", AdminListHandle)
	OnCommand(c, "cmd:admincache", AdminCacheHandle)
	OnCommand(c, "cmd:zombies", ZombiesHandle)
	OnCommand(c, "cmd:settitle", SetChatTitleHandle)
	OnCommand(c, "cmd:setdesc", SetChatDescHandle)
	OnCommand(c, "cmd:setdescription", SetChatDescHandle)

	OnCommand(c, "cmd:del", DeleteMessageHandle)
	OnCommand(c, "cmd:purge", PurgeMessagesHandle)
	OnCommand(c, "cmd:pin", PinMessageHandle)
	OnCommand(c, "cmd:unpin", UnpinMessageHandle)
	OnCommand(c, "cmd:unpinall", UnpinAllHandle)
	c.On("callback:unpinall_", UnpinAllCallback)
	OnCommand(c, "cmd:id", IDHandle)
	c.On(tg.OnParticipant, adminCacheParticipantWatcher)
}

func parseAdminError(err error, action string) string {
	if err == nil {
		return "I couldn't " + action + ". Please try again."
	}
	var fe FriendlyError
	if errors.As(err, &fe) {
		return string(fe)
	}
	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "CHAT_ADMIN_REQUIRED"):
		return "I couldn't " + action + ": I don't have the required admin rights here."
	case strings.Contains(errStr, "USER_ADMIN_INVALID"):
		return "I couldn't " + action + ": that user is an admin promoted by someone else, so I can't change them."
	case strings.Contains(errStr, "USER_NOT_PARTICIPANT"):
		return "I couldn't " + action + ": that user isn't a member of this chat."
	case strings.Contains(errStr, "USER_CREATOR"):
		return "I couldn't " + action + ": that's the chat owner."
	case strings.Contains(errStr, "USER_ID_INVALID"), strings.Contains(errStr, "PEER_ID_INVALID"), strings.Contains(errStr, "INPUT_USER_DEACTIVATED"):
		return "I couldn't " + action + ": I can't find that user. Try replying to one of their messages."
	case strings.Contains(errStr, "USER_PRIVACY_RESTRICTED"):
		return "I couldn't " + action + ": that user's privacy settings prevent it."
	case strings.Contains(errStr, "RIGHT_FORBIDDEN"):
		return "I couldn't " + action + ": I can't grant rights I don't have myself."
	case strings.Contains(errStr, "ADMIN_RANK_EMOJI_NOT_ALLOWED"):
		return "I couldn't " + action + ": admin titles can't contain emoji."
	case strings.Contains(errStr, "ADMIN_RANK_INVALID"):
		return "I couldn't " + action + ": the admin title is too long (max 16 characters) or invalid."
	case strings.Contains(errStr, "ADMINS_TOO_MUCH"):
		return "I couldn't " + action + ": this chat already has the maximum number of admins."
	case strings.Contains(errStr, "BOTS_TOO_MUCH"):
		return "I couldn't " + action + ": this chat has too many bots."
	case strings.Contains(errStr, "USER_NOT_MUTUAL_CONTACT"), strings.Contains(errStr, "USER_CHANNELS_TOO_MUCH"):
		return "I couldn't " + action + ": the user has to join the chat first."
	case strings.Contains(errStr, "USER_RESTRICTED"):
		return "I couldn't " + action + ": that account can't be managed here."
	case strings.Contains(errStr, "PARTICIPANT_ID_INVALID"):
		return "I couldn't " + action + ": the user might have left the chat."
	case strings.Contains(errStr, "CHAT_NOT_MODIFIED"), strings.Contains(errStr, "CHAT_ABOUT_NOT_MODIFIED"), strings.Contains(errStr, "MESSAGE_NOT_MODIFIED"):
		return "Nothing changed; it's already set that way."
	case strings.Contains(errStr, "CHAT_ABOUT_TOO_LONG"):
		return "I couldn't " + action + ": the description is too long (max 255 characters)."
	case strings.Contains(errStr, "CHAT_TITLE_EMPTY"):
		return "I couldn't " + action + ": the title can't be empty."
	case strings.Contains(errStr, "MESSAGE_ID_INVALID"), strings.Contains(errStr, "MESSAGE_DELETE_FORBIDDEN"):
		return "I couldn't " + action + ": the message may be deleted, too old, or not mine to touch."
	case strings.Contains(errStr, "CHANNEL_PRIVATE"), strings.Contains(errStr, "CHAT_FORBIDDEN"):
		return "I couldn't " + action + ": I'm not a member of this chat anymore."
	case strings.Contains(errStr, "CHAT_WRITE_FORBIDDEN"):
		return "I couldn't " + action + ": I'm not allowed to send messages here."
	case strings.Contains(errStr, "FLOOD_WAIT"), strings.Contains(errStr, "FLOOD_PREMIUM_WAIT"):
		return "Telegram is rate-limiting me. Please try again in a little while."
	default:
		log.Printf("Admin action '%s' failed: %v", action, err)
		return "I couldn't " + action + ". Please check my admin rights and try again."
	}
}

// ------------------ Shared moderation helpers ------------------
// Chat IDs passed to these helpers are in Bot API form (m.ChannelID(), cq.ChannelID(), pu.ChannelID()).

const (
	AnonBotID         = 1087968824
	telegramServiceID = 777000
	adminCacheTTL     = 5 * time.Minute
	adminErrTTL       = 30 * time.Second
	MinTempDuration   = time.Minute
	MaxTempDuration   = 366 * 24 * time.Hour
)

// FriendlyError carries a message that is safe to show to users as-is.
type FriendlyError string

func (e FriendlyError) Error() string { return string(e) }

type AdminInfo struct {
	UserID  int64
	Creator bool
	Rank    string
	Rights  *tg.ChatAdminRights
	User    *tg.UserObj
}

type adminSet struct {
	at     time.Time
	ttl    time.Duration
	err    error
	admins map[int64]*AdminInfo
	order  []int64
}

var adminCache = struct {
	sync.Mutex
	sets     map[int64]*adminSet
	inflight map[int64]chan struct{}
}{sets: map[int64]*adminSet{}, inflight: map[int64]chan struct{}{}}

func NormChatID(id int64) int64 {
	if id > 0 {
		return -1000000000000 - id
	}
	return id
}

func isChannelID(id int64) bool { return id < -1000000000000 }

func rawChatID(id int64) int64 {
	if isChannelID(id) {
		return -id - 1000000000000
	}
	if id < 0 {
		return -id
	}
	return id
}

// GetChatAdmins returns the cached admin list of a chat. The returned map must not be modified.
func GetChatAdmins(c *tg.Client, chatID int64) (map[int64]*AdminInfo, []int64, error) {
	chatID = NormChatID(chatID)
	for {
		adminCache.Lock()
		if s, ok := adminCache.sets[chatID]; ok && time.Since(s.at) < s.ttl {
			adminCache.Unlock()
			return s.admins, s.order, s.err
		}
		if ch, ok := adminCache.inflight[chatID]; ok {
			adminCache.Unlock()
			<-ch
			continue
		}
		ch := make(chan struct{})
		adminCache.inflight[chatID] = ch
		prev := adminCache.sets[chatID]
		adminCache.Unlock()

		admins, order, err := fetchChatAdmins(c, chatID)
		s := &adminSet{at: time.Now(), ttl: adminCacheTTL, admins: admins, order: order}
		if err != nil {
			s.ttl = adminErrTTL
			if prev != nil && prev.err == nil {
				s.admins, s.order = prev.admins, prev.order
			} else {
				s.err = err
			}
		}
		adminCache.Lock()
		adminCache.sets[chatID] = s
		delete(adminCache.inflight, chatID)
		close(ch)
		adminCache.Unlock()
		return s.admins, s.order, s.err
	}
}

func InvalidateChatAdmins(chatID int64) {
	adminCache.Lock()
	delete(adminCache.sets, NormChatID(chatID))
	adminCache.Unlock()
}

func fetchChatAdmins(c *tg.Client, chatID int64) (map[int64]*AdminInfo, []int64, error) {
	admins := map[int64]*AdminInfo{}
	var order []int64
	add := func(a *AdminInfo) {
		if _, ok := admins[a.UserID]; !ok {
			order = append(order, a.UserID)
		}
		admins[a.UserID] = a
	}
	if isChannelID(chatID) {
		ch, err := c.GetSendableChannel(chatID)
		if err != nil {
			return nil, nil, err
		}
		res, err := c.ChannelsGetParticipants(ch, &tg.ChannelParticipantsAdmins{}, 0, 200, 0)
		if err != nil {
			return nil, nil, err
		}
		obj, ok := res.(*tg.ChannelsChannelParticipantsObj)
		if !ok || obj == nil {
			return nil, nil, errors.New("unexpected participants response")
		}
		c.Cache.UpdatePeersToCache(obj.Users, obj.Chats)
		users := usersByID(obj.Users)
		for _, p := range obj.Participants {
			switch pt := p.(type) {
			case *tg.ChannelParticipantCreator:
				add(&AdminInfo{UserID: pt.UserID, Creator: true, Rank: pt.Rank, Rights: pt.AdminRights, User: users[pt.UserID]})
			case *tg.ChannelParticipantAdmin:
				add(&AdminInfo{UserID: pt.UserID, Rank: pt.Rank, Rights: pt.AdminRights, User: users[pt.UserID]})
			}
		}
		return admins, order, nil
	}

	full, err := c.MessagesGetFullChat(rawChatID(chatID))
	if err != nil {
		return nil, nil, err
	}
	c.Cache.UpdatePeersToCache(full.Users, full.Chats)
	users := usersByID(full.Users)
	cf, ok := full.FullChat.(*tg.ChatFullObj)
	if !ok || cf == nil {
		return nil, nil, errors.New("unexpected full chat response")
	}
	parts, ok := cf.Participants.(*tg.ChatParticipantsObj)
	if !ok || parts == nil {
		return nil, nil, errors.New("member list unavailable")
	}
	for _, p := range parts.Participants {
		switch pt := p.(type) {
		case *tg.ChatParticipantCreator:
			add(&AdminInfo{UserID: pt.UserID, Creator: true, Rank: pt.Rank, Rights: basicGroupAdminRights(true), User: users[pt.UserID]})
		case *tg.ChatParticipantAdmin:
			add(&AdminInfo{UserID: pt.UserID, Rank: pt.Rank, Rights: basicGroupAdminRights(false), User: users[pt.UserID]})
		}
	}
	return admins, order, nil
}

func basicGroupAdminRights(creator bool) *tg.ChatAdminRights {
	return &tg.ChatAdminRights{ChangeInfo: true, DeleteMessages: true, BanUsers: true, InviteUsers: true, PinMessages: true, ManageCall: true, AddAdmins: creator}
}

func usersByID(list []tg.User) map[int64]*tg.UserObj {
	out := make(map[int64]*tg.UserObj, len(list))
	for _, u := range list {
		if uo, ok := u.(*tg.UserObj); ok && uo != nil {
			out[uo.ID] = uo
		}
	}
	return out
}

func AdminRightAllowed(a *AdminInfo, right string) bool {
	if a == nil {
		return false
	}
	if a.Creator || right == "" {
		return true
	}
	r := a.Rights
	if r == nil {
		return false
	}
	switch right {
	case "promote":
		return r.AddAdmins
	case "ban", "restrict":
		return r.BanUsers
	case "delete":
		return r.DeleteMessages
	case "info", "change_info":
		return r.ChangeInfo
	case "pin":
		return r.PinMessages
	case "invite":
		return r.InviteUsers
	case "topics":
		return r.ManageTopics
	}
	return false
}

func GetChatAdmin(c *tg.Client, chatID, userID int64) *AdminInfo {
	if userID == 0 {
		return nil
	}
	admins, _, err := GetChatAdmins(c, chatID)
	if err != nil {
		return nil
	}
	return admins[userID]
}

// UserHasRight reports whether userID is an admin of chatID holding right ("" = any admin).
func UserHasRight(c *tg.Client, chatID, userID int64, right string) bool {
	return AdminRightAllowed(GetChatAdmin(c, chatID, userID), right)
}

func IsChatAdmin(c *tg.Client, chatID, userID int64) bool {
	return UserHasRight(c, chatID, userID, "")
}

// BotHasRight is optimistic when the admin list can't be fetched so Telegram's own error is shown instead.
func BotHasRight(c *tg.Client, chatID int64, right string) bool {
	me := c.Me()
	if me == nil {
		return true
	}
	admins, _, err := GetChatAdmins(c, chatID)
	if err != nil {
		return true
	}
	return AdminRightAllowed(admins[me.ID], right)
}

// IsAnonAdmin reports whether m was sent by an anonymous admin (posting as the group itself).
func IsAnonAdmin(m *tg.NewMessage) bool {
	if m == nil || m.Message == nil {
		return false
	}
	if pu, ok := m.Message.FromID.(*tg.PeerUser); ok && pu.UserID == AnonBotID {
		return true
	}
	pc, ok := m.Message.FromID.(*tg.PeerChannel)
	if !ok {
		return false
	}
	chat, ok := m.Message.PeerID.(*tg.PeerChannel)
	return ok && chat.ChannelID == pc.ChannelID
}

func IsGroupChat(m *tg.NewMessage) bool {
	if m == nil || m.Message == nil {
		return false
	}
	switch m.Message.PeerID.(type) {
	case *tg.PeerChat:
		return true
	case *tg.PeerChannel:
		return m.Channel == nil || !m.Channel.Broadcast
	}
	return false
}

// RequireGroup replies with an explanation and returns false outside groups.
func RequireGroup(m *tg.NewMessage) bool {
	if IsGroupChat(m) {
		return true
	}
	m.Reply("This command only works in groups.")
	return false
}

// SenderHasRight treats anonymous admins as authorized because their rights can't be inspected.
func SenderHasRight(m *tg.NewMessage, right string) bool {
	if !IsGroupChat(m) {
		return false
	}
	if IsAnonAdmin(m) {
		return true
	}
	return UserHasRight(m.Client, m.ChannelID(), m.SenderID(), right)
}

func SenderIsAdmin(m *tg.NewMessage) bool { return SenderHasRight(m, "") }

func CallbackHasRight(cq *tg.CallbackQuery, right string) bool {
	return UserHasRight(cq.Client, cq.ChannelID(), cq.GetSenderID(), right)
}

// ------------------ Target resolution ------------------

type Target struct {
	Peer      tg.InputPeer
	ID        int64
	IsChannel bool
	Name      string
	User      *tg.UserObj
}

func (t *Target) Mention() string {
	name := strings.TrimSpace(t.Name)
	if name == "" {
		name = strconv.FormatInt(t.ID, 10)
	}
	name = html.EscapeString(name)
	if t.IsChannel {
		return "<b>" + name + "</b>"
	}
	return fmt.Sprintf(`<a href="tg://user?id=%d">%s</a>`, t.ID, name)
}

var ErrNoTarget = errors.New("no target given")

func UserDisplayName(u *tg.UserObj) string {
	if u == nil {
		return ""
	}
	if u.Deleted {
		return "Deleted Account"
	}
	return strings.TrimSpace(u.FirstName + " " + u.LastName)
}

func UserMention(id int64, name string) string {
	return (&Target{ID: id, Name: name}).Mention()
}

func isArgSpace(r rune) bool { return r == ' ' || r == '\n' || r == '\t' || r == '\r' }

// CommandArgs returns everything after the command token, keeping inner newlines.
func CommandArgs(text string) string {
	text = strings.TrimLeftFunc(text, isArgSpace)
	i := strings.IndexFunc(text, isArgSpace)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(text[i:])
}

func SplitFirstArg(s string) (string, string) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, isArgSpace)
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i:])
}

// utf16ToByteOffset converts a Telegram entity offset into a byte offset of s, or -1.
func utf16ToByteOffset(s string, off int) int {
	units := 0
	for i, r := range s {
		if units == off {
			return i
		}
		if units > off {
			return -1
		}
		if r >= 0x10000 {
			units += 2
		} else {
			units++
		}
	}
	if units == off {
		return len(s)
	}
	return -1
}

// leadingMention returns the user of a text-mention entity that starts the command arguments.
func leadingMention(text string, entities []tg.MessageEntity) (int64, string, bool) {
	trimmed := strings.TrimLeftFunc(text, isArgSpace)
	lead := len(text) - len(trimmed)
	cmdEnd := strings.IndexFunc(trimmed, isArgSpace)
	if cmdEnd < 0 {
		return 0, "", false
	}
	cmdEnd += lead
	for _, e := range entities {
		mn, ok := e.(*tg.MessageEntityMentionName)
		if !ok {
			continue
		}
		start := utf16ToByteOffset(text, int(mn.Offset))
		end := utf16ToByteOffset(text, int(mn.Offset+mn.Length))
		if start < cmdEnd || end < start || strings.TrimSpace(text[cmdEnd:start]) != "" {
			continue
		}
		return mn.UserID, strings.TrimSpace(text[end:]), true
	}
	return 0, "", false
}

// looksLikeUserRef: when replying, short numbers are more likely a duration or reason than a user ID.
func looksLikeUserRef(s string, replying bool) bool {
	if len(s) > 1 && s[0] == '@' {
		return true
	}
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return false
	}
	return !replying || len(strings.TrimPrefix(s, "-")) >= 6
}

// ResolveTarget finds the user a moderation command refers to: a leading text mention,
// @username or numeric ID in the arguments, otherwise the replied-to message's sender.
// The returned string is the remaining argument text (reason, duration, title...).
func ResolveTarget(m *tg.NewMessage) (*Target, string, error) {
	text := m.Text()
	args := CommandArgs(text)
	first, rest := SplitFirstArg(args)
	if first != "" && m.Message != nil {
		if uid, after, ok := leadingMention(text, m.Message.Entities); ok {
			t, err := targetFromID(m.Client, uid)
			return t, after, err
		}
		if looksLikeUserRef(first, m.IsReply()) {
			t, err := targetFromRef(m.Client, first)
			return t, rest, err
		}
	}
	if m.IsReply() {
		reply, err := m.GetReplyMessage()
		if err != nil || reply == nil {
			return nil, args, FriendlyError("I couldn't read the replied message. It may have been deleted.")
		}
		t, err := TargetFromMessage(m, reply)
		return t, args, err
	}
	if first == "" {
		return nil, "", ErrNoTarget
	}
	return nil, args, FriendlyError(fmt.Sprintf("%s doesn't look like a user. Reply to their message, or give their @username or numeric ID.", html.EscapeString(first)))
}

// TargetFromMessage returns the sender of msg as a target. ctx is the message that holds the chat.
func TargetFromMessage(ctx, msg *tg.NewMessage) (*Target, error) {
	if msg == nil || msg.Message == nil {
		return nil, FriendlyError("I couldn't read that message.")
	}
	if pc, ok := msg.Message.FromID.(*tg.PeerChannel); ok {
		if pc.ChannelID == rawChatID(ctx.ChannelID()) {
			return nil, FriendlyError("That message was sent by an anonymous admin; I can't act on them.")
		}
		t := &Target{ID: pc.ChannelID, IsChannel: true}
		if sc := msg.SenderChat; sc != nil && sc.ID == pc.ChannelID {
			t.Peer = &tg.InputPeerChannel{ChannelID: sc.ID, AccessHash: sc.AccessHash}
			t.Name = sc.Title
			return t, nil
		}
		peer, err := ctx.Client.ResolvePeer(pc)
		if err != nil {
			return nil, FriendlyError("I couldn't identify the channel that sent that message.")
		}
		t.Peer = peer
		return t, nil
	}
	uid := msg.SenderID()
	if uid <= 0 {
		return nil, FriendlyError("I couldn't tell who sent that message.")
	}
	if uid == AnonBotID {
		return nil, FriendlyError("That message was sent by an anonymous admin; I can't act on them.")
	}
	t := &Target{ID: uid, User: msg.Sender}
	if peer, err := ctx.Client.ResolvePeer(uid); err == nil {
		t.Peer = peer
	} else if msg.Sender != nil && msg.Sender.ID == uid {
		t.Peer = &tg.InputPeerUser{UserID: uid, AccessHash: msg.Sender.AccessHash}
	} else {
		return nil, FriendlyError("I couldn't identify the sender of that message.")
	}
	if t.User == nil {
		t.User, _ = ctx.Client.GetUser(uid)
	}
	t.Name = UserDisplayName(t.User)
	return t, nil
}

func targetFromID(c *tg.Client, id int64) (*Target, error) {
	peer, err := c.ResolvePeer(id)
	if err != nil {
		return nil, FriendlyError(fmt.Sprintf("I don't know user <code>%d</code> yet. Reply to one of their messages or use their @username.", id))
	}
	return targetFromPeer(c, peer)
}

func targetFromRef(c *tg.Client, ref string) (*Target, error) {
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		if id == 0 {
			return nil, FriendlyError("0 is not a valid user ID.")
		}
		return targetFromID(c, id)
	}
	username := strings.TrimPrefix(ref, "@")
	peer, err := c.ResolvePeer(username)
	if err != nil {
		return nil, FriendlyError(fmt.Sprintf("I couldn't find anyone with the username @%s.", html.EscapeString(username)))
	}
	return targetFromPeer(c, peer)
}

func targetFromPeer(c *tg.Client, peer tg.InputPeer) (*Target, error) {
	switch p := peer.(type) {
	case *tg.InputPeerUser:
		t := &Target{Peer: p, ID: p.UserID}
		if u, err := c.GetUser(p.UserID); err == nil {
			t.User = u
			t.Name = UserDisplayName(u)
		}
		return t, nil
	case *tg.InputPeerChannel:
		t := &Target{Peer: p, ID: p.ChannelID, IsChannel: true}
		if ch, err := c.GetChannel(p.ChannelID); err == nil && ch != nil {
			t.Name = ch.Title
		}
		return t, nil
	}
	return nil, FriendlyError("That isn't a user or channel I can act on.")
}

// TargetGuard returns why action can't be applied to t in m's chat, or "" if it can.
func TargetGuard(m *tg.NewMessage, t *Target, action string) string {
	return guardFor(m.Client, m.ChannelID(), m.SenderID(), t, action)
}

func guardFor(c *tg.Client, chatID, actorID int64, t *Target, action string) string {
	if me := c.Me(); me != nil && !t.IsChannel && t.ID == me.ID {
		return "I'm not going to " + action + " myself."
	}
	if !t.IsChannel && t.ID == actorID {
		return "You can't " + action + " yourself."
	}
	if t.ID == AnonBotID || t.ID == telegramServiceID {
		return "I can't " + action + " that account."
	}
	if t.IsChannel && t.ID == rawChatID(chatID) {
		return "I can't " + action + " this chat itself."
	}
	if !t.IsChannel {
		if a := GetChatAdmin(c, chatID, t.ID); a != nil {
			if a.Creator {
				return "I can't " + action + " the chat owner."
			}
			return "I can't " + action + " an admin. Demote them first."
		}
	}
	return ""
}

// ------------------ Restriction primitives ------------------

func mutedRights(until int32) *tg.ChatBannedRights {
	return &tg.ChatBannedRights{
		SendMessages: true, SendMedia: true, SendStickers: true, SendGifs: true, SendGames: true,
		SendInline: true, EmbedLinks: true, SendPolls: true, SendPhotos: true, SendVideos: true,
		SendRoundvideos: true, SendAudios: true, SendVoices: true, SendDocs: true, SendPlain: true,
		UntilDate: until,
	}
}

func untilFor(d time.Duration) int32 {
	if d <= 0 {
		return 0
	}
	return int32(time.Now().Add(d).Unix())
}

func editChannelBanned(c *tg.Client, chatID int64, peer tg.InputPeer, rights *tg.ChatBannedRights) error {
	ch, err := c.GetSendableChannel(NormChatID(chatID))
	if err != nil {
		return err
	}
	_, err = c.ChannelsEditBanned(ch, peer, rights)
	return err
}

func removeFromBasicGroup(c *tg.Client, chatID int64, peer tg.InputPeer) error {
	u, ok := peer.(*tg.InputPeerUser)
	if !ok {
		return FriendlyError("Only users can be removed from basic groups.")
	}
	_, err := c.MessagesDeleteChatUser(false, rawChatID(chatID), &tg.InputUserObj{UserID: u.UserID, AccessHash: u.AccessHash})
	return err
}

// BanMember bans peer; d > 0 makes it temporary. Basic groups have no ban list, so the user is removed instead.
func BanMember(c *tg.Client, chatID int64, peer tg.InputPeer, d time.Duration) error {
	chatID = NormChatID(chatID)
	if !isChannelID(chatID) {
		if d > 0 {
			return FriendlyError("Temporary bans need a supergroup. In basic groups I can only remove users.")
		}
		return removeFromBasicGroup(c, chatID, peer)
	}
	return editChannelBanned(c, chatID, peer, &tg.ChatBannedRights{ViewMessages: true, UntilDate: untilFor(d)})
}

func UnbanMember(c *tg.Client, chatID int64, peer tg.InputPeer) error {
	chatID = NormChatID(chatID)
	if !isChannelID(chatID) {
		return FriendlyError("Basic groups don't keep a ban list; just add the user back.")
	}
	return editChannelBanned(c, chatID, peer, &tg.ChatBannedRights{})
}

// KickMember removes peer with an immediate ban and unban so they can rejoin.
func KickMember(c *tg.Client, chatID int64, peer tg.InputPeer) error {
	chatID = NormChatID(chatID)
	if !isChannelID(chatID) {
		return removeFromBasicGroup(c, chatID, peer)
	}
	if err := editChannelBanned(c, chatID, peer, &tg.ChatBannedRights{ViewMessages: true}); err != nil {
		return err
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = editChannelBanned(c, chatID, peer, &tg.ChatBannedRights{}); err == nil {
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	log.Printf("kick: unban after kick failed in %d: %v", chatID, err)
	return FriendlyError("They were removed, but I couldn't unban them afterwards. Use /unban to let them rejoin.")
}

func MuteMember(c *tg.Client, chatID int64, peer tg.InputPeer, d time.Duration) error {
	chatID = NormChatID(chatID)
	if !isChannelID(chatID) {
		return FriendlyError("Muting needs a supergroup; basic groups don't support per-user restrictions.")
	}
	if _, ok := peer.(*tg.InputPeerChannel); ok {
		return FriendlyError("Channels can't be muted, only banned.")
	}
	return editChannelBanned(c, chatID, peer, mutedRights(untilFor(d)))
}

func UnmuteMember(c *tg.Client, chatID int64, peer tg.InputPeer) error {
	chatID = NormChatID(chatID)
	if !isChannelID(chatID) {
		return FriendlyError("Basic groups don't support per-user restrictions.")
	}
	return editChannelBanned(c, chatID, peer, &tg.ChatBannedRights{})
}

// ------------------ Durations & errors ------------------

var durationUnits = map[string]time.Duration{
	"":  time.Minute,
	"s": time.Second, "sec": time.Second, "secs": time.Second, "second": time.Second, "seconds": time.Second,
	"m": time.Minute, "min": time.Minute, "mins": time.Minute, "minute": time.Minute, "minutes": time.Minute,
	"h": time.Hour, "hr": time.Hour, "hrs": time.Hour, "hour": time.Hour, "hours": time.Hour,
	"d": 24 * time.Hour, "day": 24 * time.Hour, "days": 24 * time.Hour,
	"w": 7 * 24 * time.Hour, "wk": 7 * 24 * time.Hour, "week": 7 * 24 * time.Hour, "weeks": 7 * 24 * time.Hour,
}

// ParseAdminDuration parses durations like 30s, 10m, 2h, 3d, 1w or 1h30m. A bare number means minutes.
// An empty string yields 0 with no error.
func ParseAdminDuration(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, nil
	}
	invalid := FriendlyError(fmt.Sprintf("<code>%s</code> isn't a valid duration. Use something like 30m, 2h, 3d or 1w.", html.EscapeString(s)))
	var total time.Duration
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i || j-i > 7 {
			return 0, invalid
		}
		n, _ := strconv.Atoi(s[i:j])
		k := j
		for k < len(s) && s[k] >= 'a' && s[k] <= 'z' {
			k++
		}
		unit, ok := durationUnits[s[j:k]]
		if !ok {
			return 0, invalid
		}
		total += time.Duration(n) * unit
		if total > 10*MaxTempDuration {
			return 0, FriendlyError("That duration is too long. The maximum is 366 days.")
		}
		i = k
	}
	return total, nil
}

// ParseTempDuration parses and validates a duration for temporary bans/mutes.
func ParseTempDuration(s string) (time.Duration, error) {
	d, err := ParseAdminDuration(s)
	if err != nil {
		return 0, err
	}
	switch {
	case d == 0:
		return 0, FriendlyError("Please give a duration, e.g. 30m, 2h, 3d or 1w.")
	case d < MinTempDuration:
		return 0, FriendlyError("The duration must be at least 1 minute.")
	case d > MaxTempDuration:
		return 0, FriendlyError("The duration can be at most 366 days.")
	}
	return d, nil
}
