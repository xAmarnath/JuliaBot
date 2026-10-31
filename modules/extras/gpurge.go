package extras

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	modules "main/modules"
)

const (
	gpurgeMaxN       = 200
	gpurgeMaxScan    = 1000
	gpurgeMaxRange   = 3000
	gpurgeBatch      = 100
	gpurgeBatchPause = 400 * time.Millisecond
)

func isSupergroupID(chat int64) bool { return chat < -1000000000000 }

func gpurgeChunkedDelete(client *tg.Client, chat int64, ids []int32) (int, error) {
	deleted := 0
	for i := 0; i < len(ids); i += gpurgeBatch {
		end := min(i+gpurgeBatch, len(ids))
		if _, err := client.DeleteMessages(chat, ids[i:end]); err != nil {
			return deleted, err
		}
		deleted += end - i
		if end < len(ids) {
			time.Sleep(gpurgeBatchPause)
		}
	}
	return deleted, nil
}

// gpurgeIDRanges splits the IDs below fromID (newest first) into batches, scanning at most depth IDs.
func gpurgeIDRanges(fromID int32, depth int) [][]int32 {
	var out [][]int32
	var cur []int32
	for id := fromID - 1; id > 0 && int(fromID-id) <= depth; id-- {
		cur = append(cur, id)
		if len(cur) == gpurgeBatch {
			out = append(out, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// gpurgeScan collects up to limit message IDs below fromID in chat whose sender is senderID.
// Bots can't read history, so messages are fetched by ID.
func gpurgeScan(c *tg.Client, chat int64, fromID int32, depth int, senderID int64, limit int) ([]int32, error) {
	var ids []int32
	for _, batch := range gpurgeIDRanges(fromID, depth) {
		msgs, err := c.GetMessages(chat, &tg.SearchOption{IDs: batch})
		if err != nil {
			return ids, err
		}
		for i := range msgs {
			msg := &msgs[i]
			if msg.Message == nil || msg.IsEmpty() || msg.ChannelID() != chat || msg.SenderID() != senderID {
				continue
			}
			ids = append(ids, msg.ID)
			if len(ids) >= limit {
				return ids, nil
			}
		}
	}
	return ids, nil
}

// gpurgeFilterChat keeps only IDs that belong to chat. In basic groups message IDs are shared across
// all of the bot's chats, so a raw range would hit other chats.
func gpurgeFilterChat(c *tg.Client, chat int64, ids []int32) ([]int32, error) {
	if isSupergroupID(chat) {
		return ids, nil
	}
	var out []int32
	for i := 0; i < len(ids); i += gpurgeBatch {
		end := min(i+gpurgeBatch, len(ids))
		msgs, err := c.GetMessages(chat, &tg.SearchOption{IDs: ids[i:end]})
		if err != nil {
			return out, err
		}
		for j := range msgs {
			if msgs[j].Message != nil && !msgs[j].IsEmpty() && msgs[j].ChannelID() == chat {
				out = append(out, msgs[j].ID)
			}
		}
	}
	return out, nil
}

func parsePurgeCount(m *tg.NewMessage, usage string) (int, bool) {
	first, _ := modules.SplitFirstArg(modules.CommandArgs(m.Text()))
	if first == "" {
		m.Reply("<b>Usage:</b> " + usage)
		return 0, false
	}
	n, err := strconv.Atoi(first)
	if err != nil || n <= 0 {
		m.Reply("<b>Invalid count.</b> Give a positive whole number, e.g. " + usage)
		return 0, false
	}
	if n > gpurgeMaxN {
		m.Reply(fmt.Sprintf("<b>Count too high.</b> The maximum is %d.", gpurgeMaxN))
		return 0, false
	}
	return n, true
}

func gpurgeScanDepth(n int) int {
	return min(max(n*5, 100), gpurgeMaxScan)
}

func SilentPurgeHandle(m *tg.NewMessage) error {
	if !modules.IsGroupChat(m) {
		return nil
	}
	chat := m.ChannelID()
	if !modules.SenderHasRight(m, "delete") {
		modules.ReplyTemp(m, "You need the <b>Delete Messages</b> admin right.", 5)
		m.Delete()
		return nil
	}
	if !modules.BotHasRight(m.Client, chat, "delete") {
		modules.ReplyTemp(m, "I need the <b>Delete Messages</b> admin right.", 5)
		return nil
	}
	if !m.IsReply() {
		modules.ReplyTemp(m, "Reply to the first message you want gone, then send <code>/spurge</code>.", 5)
		m.Delete()
		return nil
	}

	startID := m.ReplyToMsgID()
	endID := m.ID
	if startID <= 0 || startID > endID {
		m.Delete()
		return nil
	}
	if int(endID-startID) >= gpurgeMaxRange {
		startID = endID - gpurgeMaxRange + 1
	}

	ids := make([]int32, 0, endID-startID+1)
	for i := startID; i <= endID; i++ {
		ids = append(ids, i)
	}
	ids, err := gpurgeFilterChat(m.Client, chat, ids)
	if err != nil {
		modules.ReplyTemp(m, modules.AdminFriendlyError(err, "purge"), 5)
		return nil
	}
	if _, err := gpurgeChunkedDelete(m.Client, chat, ids); err != nil {
		modules.ReplyTemp(m, modules.AdminFriendlyError(err, "purge"), 5)
	}
	return nil
}

func UserPurgeHandle(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	chat := m.ChannelID()
	if !modules.SenderHasRight(m, "delete") {
		m.Reply("You need the <b>Delete Messages</b> admin right.")
		return nil
	}
	if !modules.BotHasRight(m.Client, chat, "delete") {
		m.Reply("I need the <b>Delete Messages</b> admin right.")
		return nil
	}
	if !m.IsReply() {
		m.Reply("Reply to one of the user's messages: <code>/upurge &lt;N&gt;</code>")
		return nil
	}
	n, ok := parsePurgeCount(m, "<code>/upurge 20</code>")
	if !ok {
		return nil
	}

	reply, err := m.GetReplyMessage()
	if err != nil || reply == nil {
		m.Reply("I couldn't read the replied message. It may have been deleted.")
		return nil
	}
	target, err := modules.TargetFromMessage(m, reply)
	if err != nil {
		m.Reply(modules.AdminFriendlyError(err, "purge"))
		return nil
	}
	if a := modules.GetChatAdmin(m.Client, chat, target.ID); a != nil && !target.IsChannel && target.ID != m.SenderID() {
		if a.Creator || !modules.UserHasRight(m.Client, chat, m.SenderID(), "promote") {
			m.Reply("I won't purge another admin's messages.")
			return nil
		}
	}

	ids, err := gpurgeScan(m.Client, chat, m.ID, gpurgeScanDepth(n), target.ID, n)
	if err != nil && len(ids) == 0 {
		m.Reply(modules.AdminFriendlyError(err, "scan recent messages"))
		return nil
	}
	if len(ids) == 0 {
		modules.ReplyTemp(m, "No recent messages from "+target.Mention()+" found.", 5)
		return nil
	}

	deleted, derr := gpurgeChunkedDelete(m.Client, chat, ids)
	if derr != nil && deleted == 0 {
		m.Reply(modules.AdminFriendlyError(derr, "delete messages"))
		return nil
	}
	m.Delete()
	modules.ReplyTemp(m, fmt.Sprintf("Deleted <b>%d</b> message(s) from %s.", deleted, target.Mention()), 5)
	return nil
}

func MyPurgeHandle(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	chat := m.ChannelID()
	senderID := m.SenderID()
	if senderID == 0 || modules.IsAnonAdmin(m) {
		m.Reply("Anonymous admins can't use <code>/mypurge</code>.")
		return nil
	}
	n, ok := parsePurgeCount(m, "<code>/mypurge 10</code>")
	if !ok {
		return nil
	}
	if !modules.BotHasRight(m.Client, chat, "delete") {
		m.Reply("I need the <b>Delete Messages</b> admin right to remove your messages.")
		return nil
	}

	ids, err := gpurgeScan(m.Client, chat, m.ID, gpurgeScanDepth(n), senderID, n)
	if err != nil && len(ids) == 0 {
		m.Reply(modules.AdminFriendlyError(err, "scan recent messages"))
		return nil
	}
	if len(ids) == 0 {
		modules.ReplyTemp(m, "No recent messages of yours found.", 5)
		m.Delete()
		return nil
	}
	ids = append(ids, m.ID)
	if _, err := gpurgeChunkedDelete(m.Client, chat, ids); err != nil {
		m.Reply(modules.AdminFriendlyError(err, "delete messages"))
	}
	return nil
}

func registerGPurgeHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:spurge", SilentPurgeHandle)
	modules.OnCommand(c, "cmd:upurge", UserPurgeHandle)
	modules.OnCommand(c, "cmd:mypurge", MyPurgeHandle)
}

func init() {
	modules.QueueHandlerRegistration(registerGPurgeHandlers)

	modules.Mods.AddModule("GPurge", strings.TrimSpace(`<b>Targeted Purge</b>

Purge tools that go beyond the basic <code>/purge</code> range.

<b>Commands:</b>
 - <code>/spurge</code> - Silent purge. Reply to a message; deletes everything from that message up to and including the command, with no status message. At most 3000 messages per run.
 - <code>/upurge &lt;N&gt;</code> - Reply to a user's message; deletes that user's last N messages (looks back up to 1000 messages).
 - <code>/mypurge &lt;N&gt;</code> - Deletes your own last N messages plus the command (looks back up to 1000 messages).

<b>Examples:</b>
 <code>/upurge 20</code> (as a reply) - remove the last 20 messages of that user
 <code>/mypurge 5</code> - remove your last 5 messages

<b>Limits &amp; permissions:</b>
 - N is 1-200.
 - <code>/spurge</code> and <code>/upurge</code> need the Delete Messages right; <code>/upurge</code> won't touch other admins' messages unless you can add admins.
 - <code>/mypurge</code> is open to everyone.
 - I need the Delete Messages right for all of them.`))
}
