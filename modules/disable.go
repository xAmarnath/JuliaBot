package modules

import (
	"encoding/json"
	"fmt"
	"html"
	"main/internal/mongostore"
	"main/modules/db"
	"sort"
	"strconv"
	"strings"
	"sync"

	tg "github.com/xAmarnath/gogram/telegram"
)

const disabledBucket = "disabled_cmds"

var (
	disabledMu        sync.RWMutex
	disabledCache     = map[int64]map[string]bool{}
	commandNames      = map[string]bool{}
	commandNameMu     sync.RWMutex
	disabledEditLocks [64]sync.Mutex
)

var undisableable = map[string]bool{"disable": true, "enable": true, "disabled": true, "help": true, "start": true}

func OnCommand(c *tg.Client, pattern string, handler any, filters ...tg.Filter) tg.Handle {
	name := strings.ToLower(strings.TrimPrefix(pattern, "cmd:"))
	commandNameMu.Lock()
	commandNames[name] = true
	commandNameMu.Unlock()
	if h, ok := handler.(func(*tg.NewMessage) error); ok && !undisableable[name] {
		inner := h
		handler = func(m *tg.NewMessage) error {
			if commandDisabledFor(m, name) {
				return nil
			}
			return inner(m)
		}
	}
	args := []any{pattern, handler}
	for _, f := range filters {
		args = append(args, f)
	}
	return c.On(args...)
}

func commandDisabledFor(m *tg.NewMessage, name string) bool {
	if m == nil || m.IsPrivate() {
		return false
	}
	if !disabledCommands(m.ChatID())[name] {
		return false
	}
	return !IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "")
}

// Apply the same group command policy to inline game actions.
func CallbackCommandDisabled(c *tg.CallbackQuery, name string) bool {
	return !c.IsPrivate() && disabledCommands(c.GetChatID())[name] &&
		!IsUserAdmin(c.Client, c.SenderID, c.ChannelID(), "")
}

func disabledCommands(chatID int64) map[string]bool {
	disabledMu.RLock()
	set, ok := disabledCache[chatID]
	disabledMu.RUnlock()
	if ok {
		return set
	}
	set = map[string]bool{}
	if database, err := db.GetDB(); err == nil && database != nil {
		_ = database.View(func(tx *mongostore.Tx) error {
			b := tx.Bucket([]byte(disabledBucket))
			if b == nil {
				return nil
			}
			var names []string
			if v := b.Get([]byte(strconv.FormatInt(chatID, 10))); len(v) > 0 && json.Unmarshal(v, &names) == nil {
				for _, n := range names {
					set[n] = true
				}
			}
			return nil
		})
	}
	disabledMu.Lock()
	if cached, exists := disabledCache[chatID]; exists {
		set = cached
	} else {
		disabledCache[chatID] = set
	}
	disabledMu.Unlock()
	return set
}

func saveDisabledCommands(chatID int64, set map[string]bool) error {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	database, err := db.GetDB()
	if err != nil || database == nil {
		return fmt.Errorf("database unavailable")
	}
	err = database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(disabledBucket))
		if err != nil {
			return err
		}
		key := []byte(strconv.FormatInt(chatID, 10))
		if len(names) == 0 {
			return b.Delete(key)
		}
		data, _ := json.Marshal(names)
		return b.Put(key, data)
	})
	if err == nil {
		disabledMu.Lock()
		disabledCache[chatID] = set
		disabledMu.Unlock()
	}
	return err
}

func parseCommandNames(args string) []string {
	var out []string
	for _, f := range strings.Fields(strings.ToLower(args)) {
		f = strings.TrimLeft(f, "/.!-?")
		if i := strings.IndexByte(f, '@'); i > 0 {
			f = f[:i]
		}
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func disableAdminGuard(m *tg.NewMessage) bool {
	if m.IsPrivate() {
		m.Reply("This command only works in groups.")
		return false
	}
	if !IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "") {
		m.Reply("Only admins can change which commands are disabled.")
		return false
	}
	return true
}

func toggleCommands(m *tg.NewMessage, disable bool) error {
	if !disableAdminGuard(m) {
		return nil
	}
	names := parseCommandNames(m.Args())
	verb := "enable"
	if disable {
		verb = "disable"
	}
	if len(names) == 0 {
		m.Reply(fmt.Sprintf("Usage: <code>/%s &lt;command&gt; [more commands]</code>", verb))
		return nil
	}
	lock := &disabledEditLocks[uint64(m.ChatID())%uint64(len(disabledEditLocks))]
	lock.Lock()
	defer lock.Unlock()
	current := disabledCommands(m.ChatID())
	next := make(map[string]bool, len(current))
	for k := range current {
		next[k] = true
	}
	var changed, unknown, locked []string
	commandNameMu.RLock()
	for _, n := range names {
		switch {
		case !commandNames[n]:
			unknown = append(unknown, n)
		case disable && undisableable[n]:
			locked = append(locked, n)
		case disable && !next[n]:
			next[n] = true
			changed = append(changed, n)
		case !disable && next[n]:
			delete(next, n)
			changed = append(changed, n)
		}
	}
	commandNameMu.RUnlock()
	if len(changed) > 0 {
		if err := saveDisabledCommands(m.ChatID(), next); err != nil {
			m.Reply("I couldn't save that. Please try again.")
			return nil
		}
	}
	var b strings.Builder
	if len(changed) > 0 {
		fmt.Fprintf(&b, "<b>%sd:</b> %s\n", strings.ToUpper(verb[:1])+verb[1:], html.EscapeString("/"+strings.Join(changed, ", /")))
	} else {
		fmt.Fprintf(&b, "Nothing to %s.\n", verb)
	}
	if len(unknown) > 0 {
		fmt.Fprintf(&b, "<b>Unknown:</b> %s\n", html.EscapeString(strings.Join(unknown, ", ")))
	}
	if len(locked) > 0 {
		fmt.Fprintf(&b, "<b>Can't be disabled:</b> %s\n", html.EscapeString(strings.Join(locked, ", ")))
	}
	if disable && len(changed) > 0 {
		b.WriteString("<i>Admins can still use disabled commands.</i>")
	}
	m.Reply(strings.TrimSpace(b.String()))
	return nil
}

func DisableHandler(m *tg.NewMessage) error { return toggleCommands(m, true) }
func EnableHandler(m *tg.NewMessage) error  { return toggleCommands(m, false) }

func DisabledListHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("This command only works in groups.")
		return nil
	}
	set := disabledCommands(m.ChatID())
	if len(set) == 0 {
		m.Reply("No commands are disabled in this chat.")
		return nil
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, "/"+n)
	}
	sort.Strings(names)
	m.Reply("<b>Disabled commands:</b>\n" + html.EscapeString(strings.Join(names, "\n")))
	return nil
}

func init() {
	QueueHandlerRegistration(func() {
		c := Client
		OnCommand(c, "cmd:disable", DisableHandler)
		OnCommand(c, "cmd:enable", EnableHandler)
		OnCommand(c, "cmd:disabled", DisabledListHandler)
	})
	Mods.AddModule("Disabling", `<b>Disabling Commands</b>

Admins can turn off commands they don't want members to use in their group.

<code>/disable &lt;command&gt; [more]</code> — disable one or more commands
<code>/enable &lt;command&gt; [more]</code> — enable them again
<code>/disabled</code> — list disabled commands in this chat

Members' disabled commands are ignored silently; admins can still use them.
<code>/disable</code>, <code>/enable</code>, <code>/help</code> and <code>/start</code> can't be disabled.

Example: <code>/disable kang gif paste</code>`)
}
