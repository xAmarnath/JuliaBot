package extras

import (
	"fmt"
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
	silentBucket      = "silent_cfg"
	silentDeleteDelay = 5 * time.Second
)

var (
	silentMu    sync.RWMutex
	silentCache = make(map[int64]bool)
)

var silentModCommands = map[string]bool{
	"ban": true, "unban": true, "tban": true, "sban": true, "dban": true,
	"kick": true, "skick": true, "dkick": true,
	"mute": true, "unmute": true, "tmute": true, "smute": true, "dmute": true,
	"warn": true, "twarn": true, "rmwarn": true, "resetwarns": true,
	"promote": true, "fullpromote": true, "demote": true,
	"pin": true, "unpin": true, "purge": true, "del": true,
	"lock": true, "unlock": true,
}

// IsSilent reports whether silent mode is on for chatID (the m.ChatID() key). Cached after the first lookup.
func IsSilent(chatID int64) bool {
	silentMu.RLock()
	v, ok := silentCache[chatID]
	silentMu.RUnlock()
	if ok {
		return v
	}
	database, err := db.GetDB()
	if err != nil || database == nil {
		return false
	}
	enabled := false
	if err := database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(silentBucket))
		if b == nil {
			return nil
		}
		enabled = string(b.Get([]byte(strconv.FormatInt(chatID, 10)))) == "1"
		return nil
	}); err != nil {
		return false
	}
	silentMu.Lock()
	silentCache[chatID] = enabled
	silentMu.Unlock()
	return enabled
}

func setSilent(chatID int64, enabled bool) error {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return fmt.Errorf("db unavailable")
	}
	err = database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(silentBucket))
		if err != nil {
			return err
		}
		val := []byte("0")
		if enabled {
			val = []byte("1")
		}
		return b.Put([]byte(strconv.FormatInt(chatID, 10)), val)
	})
	if err != nil {
		return err
	}
	silentMu.Lock()
	silentCache[chatID] = enabled
	silentMu.Unlock()
	return nil
}

// silentCommandName extracts the lowercase command from text like "/ban@Bot x", or "" if text isn't a command.
func silentCommandName(text string) string {
	if len(text) < 2 || !strings.ContainsRune("./!-?", rune(text[0])) {
		return ""
	}
	cmd := text[1:]
	if i := strings.IndexAny(cmd, " \n\t@"); i >= 0 {
		cmd = cmd[:i]
	}
	return strings.ToLower(cmd)
}

func SilentWatcher(m *tg.NewMessage) error {
	if m == nil || m.Message == nil || m.IsPrivate() {
		return nil
	}
	if !silentModCommands[silentCommandName(m.Text())] {
		return nil
	}
	if !IsSilent(m.ChatID()) || !modules.BotHasRight(m.Client, m.ChannelID(), "delete") {
		return nil
	}
	chat, id, client := m.ChannelID(), m.ID, m.Client
	// Delayed so the command handler can still resolve the message it replies to.
	time.AfterFunc(silentDeleteDelay, func() {
		_, _ = client.DeleteMessages(chat, []int32{id})
	})
	return nil
}

func SilentHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "change_info") {
		m.Reply("You need the <b>Change Group Info</b> admin right to manage silent mode.")
		return nil
	}

	arg, _ := modules.SplitFirstArg(modules.CommandArgs(m.Text()))
	switch strings.ToLower(arg) {
	case "on", "enable", "yes", "1":
		if err := setSilent(m.ChatID(), true); err != nil {
			m.Reply("I couldn't save that setting. Please try again.")
			return nil
		}
		msg := "Silent mode <b>enabled</b>. Moderation commands will be deleted a few seconds after they run."
		if !modules.BotHasRight(m.Client, m.ChannelID(), "delete") {
			msg += "\n\n<i>Note: I need the Delete Messages right for this to work.</i>"
		}
		m.Reply(msg)
	case "off", "disable", "no", "0":
		if err := setSilent(m.ChatID(), false); err != nil {
			m.Reply("I couldn't save that setting. Please try again.")
			return nil
		}
		m.Reply("Silent mode <b>disabled</b>.")
	case "", "status":
		state := "off"
		if IsSilent(m.ChatID()) {
			state = "on"
		}
		m.Reply("Silent mode is <b>" + state + "</b>.\nUsage: <code>/silent on|off|status</code>")
	default:
		m.Reply("Usage: <code>/silent on|off|status</code>")
	}
	return nil
}

func registerSilentHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:silent", SilentHandler)
	c.On(tg.OnNewMessage, SilentWatcher)
}

func init() {
	modules.QueueHandlerRegistration(registerSilentHandlers)

	modules.Mods.AddModule("SilentMode", `<b>Silent Mode</b>

Keeps the chat tidy by deleting moderation command messages (e.g. <code>/ban</code>, <code>/mute</code>, <code>/warn</code>, <code>/pin</code>, <code>/purge</code>, <code>/lock</code>) about 5 seconds after they are sent. The commands still run normally.

<b>Commands:</b>
 - <code>/silent on</code> - Enable silent mode
 - <code>/silent off</code> - Disable silent mode
 - <code>/silent</code> or <code>/silent status</code> - Show the current state

<b>Requirements:</b>
 - You need the Change Group Info admin right.
 - I need the Delete Messages admin right.`)
}
