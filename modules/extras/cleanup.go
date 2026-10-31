package extras

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"main/modules/db"
	"strconv"
	"strings"
	"sync"
	"time"

	modules "main/modules"

	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
)

const cleanupBucket = "cleanup_cfg"

type cleanupCfg struct {
	Enabled bool `json:"enabled"`
	Delay   int  `json:"delay"`
	Pinned  bool `json:"pinned"`
}

var (
	cleanupCache   = make(map[int64]*cleanupCfg)
	cleanupCacheMu sync.RWMutex
)

func cleanupKey(chatID int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(chatID))
	return b
}

func defaultCleanupCfg() *cleanupCfg {
	return &cleanupCfg{Enabled: false, Delay: 2, Pinned: false}
}

func loadCleanupCfg(chatID int64) *cleanupCfg {
	cleanupCacheMu.RLock()
	if v, ok := cleanupCache[chatID]; ok {
		cp := *v
		cleanupCacheMu.RUnlock()
		return &cp
	}
	cleanupCacheMu.RUnlock()

	cfg := defaultCleanupCfg()
	d, err := db.GetDB()
	if err != nil || d == nil {
		return cfg
	}
	_ = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(cleanupBucket))
		if b == nil {
			return nil
		}
		raw := b.Get(cleanupKey(chatID))
		if len(raw) == 0 {
			return nil
		}
		_ = json.Unmarshal(raw, cfg)
		return nil
	})
	if cfg.Delay < 0 {
		cfg.Delay = 2
	}

	cleanupCacheMu.Lock()
	cp := *cfg
	cleanupCache[chatID] = &cp
	cleanupCacheMu.Unlock()
	return cfg
}

func saveCleanupCfg(chatID int64, cfg *cleanupCfg) error {
	d, err := db.GetDB()
	if err != nil || d == nil {
		return fmt.Errorf("db unavailable")
	}
	err = d.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(cleanupBucket))
		if err != nil {
			return err
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return b.Put(cleanupKey(chatID), raw)
	})
	if err != nil {
		return err
	}
	cleanupCacheMu.Lock()
	cp := *cfg
	cleanupCache[chatID] = &cp
	cleanupCacheMu.Unlock()
	return nil
}

func formatCleanupCfg(cfg *cleanupCfg) string {
	state := "off"
	if cfg.Enabled {
		state = "on"
	}
	pinned := "off"
	if cfg.Pinned {
		pinned = "on"
	}
	var sb strings.Builder
	sb.WriteString("<b>Service Message Cleanup</b>\n\n")
	fmt.Fprintf(&sb, " - <b>Status:</b> <code>%s</code>\n", state)
	fmt.Fprintf(&sb, " - <b>Delay:</b> <code>%d seconds</code>\n", cfg.Delay)
	fmt.Fprintf(&sb, " - <b>Pinned messages:</b> <code>%s</code>\n", pinned)
	sb.WriteString("\n<b>Usage:</b>\n")
	sb.WriteString(" - <code>/cleanup on</code> - Enable auto-delete\n")
	sb.WriteString(" - <code>/cleanup off</code> - Disable auto-delete\n")
	sb.WriteString(" - <code>/cleanup status</code> - Show current config\n")
	sb.WriteString(" - <code>/cleanup delay &lt;seconds&gt;</code> - Set delete delay (default 2)\n")
	sb.WriteString(" - <code>/cleanup pinned on|off</code> - Also clean pinned-notice service messages\n")
	return sb.String()
}

func CleanupHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}

	cfg := loadCleanupCfg(m.ChatID())
	args := strings.Fields(modules.CommandArgs(m.Text()))
	if len(args) == 0 {
		m.Reply(formatCleanupCfg(cfg))
		return nil
	}
	sub := strings.ToLower(args[0])
	if sub == "status" || sub == "show" {
		m.Reply(formatCleanupCfg(cfg))
		return nil
	}

	if !modules.SenderHasRight(m, "delete") {
		m.Reply("You need the <b>Delete Messages</b> admin right to change cleanup settings.")
		return nil
	}

	save := func(ok string) {
		if err := saveCleanupCfg(m.ChatID(), cfg); err != nil {
			m.Reply("I couldn't save that setting. Please try again.")
			return
		}
		if cfg.Enabled && !modules.BotHasRight(m.Client, m.ChannelID(), "delete") {
			ok += "\n\n<i>Note: I need the Delete Messages right to remove service messages.</i>"
		}
		m.Reply(ok)
	}

	switch sub {
	case "on", "enable", "yes":
		cfg.Enabled = true
		save(fmt.Sprintf("<b>Cleanup enabled.</b> Service messages will be deleted after %d seconds.", cfg.Delay))
	case "off", "disable", "no":
		cfg.Enabled = false
		save("<b>Cleanup disabled.</b>")
	case "delay":
		if len(args) < 2 {
			m.Reply("<b>Usage:</b> <code>/cleanup delay &lt;seconds&gt;</code> (0-3600)")
			return nil
		}
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 0 || n > 3600 {
			m.Reply("<b>Invalid delay.</b> Use a whole number of seconds from 0 to 3600.")
			return nil
		}
		cfg.Delay = n
		save(fmt.Sprintf("<b>Delay set to %d seconds.</b>", n))
	case "pinned":
		if len(args) < 2 {
			m.Reply("<b>Usage:</b> <code>/cleanup pinned on|off</code>")
			return nil
		}
		switch strings.ToLower(args[1]) {
		case "on", "enable", "yes":
			cfg.Pinned = true
		case "off", "disable", "no":
			cfg.Pinned = false
		default:
			m.Reply("<b>Usage:</b> <code>/cleanup pinned on|off</code>")
			return nil
		}
		state := "off"
		if cfg.Pinned {
			state = "on"
		}
		save(fmt.Sprintf("<b>Pinned-notice cleanup:</b> <code>%s</code>", state))
	default:
		m.Reply(formatCleanupCfg(cfg))
	}
	return nil
}

// cleanupSkipAction reports service messages that must never be deleted.
func cleanupSkipAction(a tg.MessageAction, cfg *cleanupCfg) bool {
	switch a.(type) {
	case nil, *tg.MessageActionEmpty:
		return true
	case *tg.MessageActionTopicCreate:
		// Deleting a topic's creation message deletes the whole topic.
		return true
	case *tg.MessageActionPinMessage:
		return !cfg.Pinned
	}
	return false
}

func CleanupWatcher(m *tg.NewMessage) error {
	if m == nil || m.Message == nil || m.IsPrivate() || !m.IsService() {
		return nil
	}
	cfg := loadCleanupCfg(m.ChatID())
	if !cfg.Enabled || cleanupSkipAction(m.Action, cfg) {
		return nil
	}
	if !modules.BotHasRight(m.Client, m.ChannelID(), "delete") {
		return nil
	}

	chat, id, client := m.ChannelID(), m.ID, m.Client
	del := func() { _, _ = client.DeleteMessages(chat, []int32{id}) }
	if cfg.Delay <= 0 {
		go del()
		return nil
	}
	time.AfterFunc(time.Duration(cfg.Delay)*time.Second, del)
	return nil
}

func registerCleanupHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:cleanup", CleanupHandler)
	c.On(tg.OnAction, CleanupWatcher)
}

func init() {
	modules.QueueHandlerRegistration(registerCleanupHandlers)

	modules.Mods.AddModule("Cleanup", `<b>Service Message Cleanup</b>

Automatically deletes service messages such as "X joined", "X left", "X added Y", title/photo changes and (optionally) "X pinned a message". Forum topic-creation messages are never touched.

<b>Commands:</b>
 - <code>/cleanup</code> or <code>/cleanup status</code> - Show the current settings
 - <code>/cleanup on</code> / <code>/cleanup off</code> - Enable or disable
 - <code>/cleanup delay &lt;seconds&gt;</code> - Wait this long before deleting (0-3600, default 2; 0 = immediately)
 - <code>/cleanup pinned on|off</code> - Also delete "pinned a message" notices

<b>Example:</b>
 <code>/cleanup delay 30</code> - keep join notices visible for 30 seconds

<b>Permissions:</b> Changing settings needs the Delete Messages right; I need it too.`)
}
