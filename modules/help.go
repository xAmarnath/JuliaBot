package modules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/xAmarnath/gogram/telegram"
)

type Modules struct {
	mu  sync.RWMutex
	Mod []Mod
}

type Mod struct {
	Name string
	Help string
}

const helpPageLimit = 3500

func (m *Modules) AddModule(name, help string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, v := range m.Mod {
		if strings.EqualFold(v.Name, name) {
			m.Mod[i].Help = help
			return
		}
	}
	m.Mod = append(m.Mod, Mod{name, help})
}

func (m *Modules) GetHelp(name string) string {
	if mod, ok := m.find(name); ok {
		return mod.Help
	}
	return ""
}

var helpGroups = map[string]string{
	"afkstatus":  "AFK",
	"anime":      "Misc",
	"birthday":   "Misc",
	"crypto":     "Misc",
	"ephemeral":  "Misc",
	"lookup":     "Misc",
	"profile":    "Misc",
	"qr":         "Misc",
	"snipe":      "Tools",
	"tamilmv":    "Tools",
	"kisskh":     "Tools",
	"kisswatch":  "Tools",
	"chatstats":  "Tools",
	"temprules":  "Rules",
	"silentmode": "Admin",
	"files":      "Dev",
	"start":      "Dev",
}

func helpSection(name string) string {
	if g, ok := helpGroups[strings.ToLower(name)]; ok {
		return g
	}
	return name
}

func (m *Modules) grouped() []Mod {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var order []string
	parts := map[string][]string{}
	for _, v := range m.Mod {
		sec := helpSection(v.Name)
		key := strings.ToLower(sec)
		if _, ok := parts[key]; !ok {
			order = append(order, sec)
		}
		if strings.EqualFold(v.Name, sec) {
			parts[key] = append([]string{v.Help}, parts[key]...)
		} else {
			parts[key] = append(parts[key], v.Help)
		}
	}
	out := make([]Mod, 0, len(order))
	for _, sec := range order {
		out = append(out, Mod{Name: sec, Help: strings.Join(parts[strings.ToLower(sec)], "\n\n━━━━━━━━━━━━\n\n")})
	}
	return out
}

func (m *Modules) find(name string) (Mod, bool) {
	name = strings.TrimSpace(name)
	mods := m.grouped()
	target := helpSection(name)
	for _, v := range mods {
		if strings.EqualFold(v.Name, target) {
			return v, true
		}
	}
	var match Mod
	n := 0
	for _, v := range mods {
		if strings.Contains(strings.ToLower(v.Name), strings.ToLower(name)) {
			match = v
			n++
		}
	}
	return match, n == 1
}

func (m *Modules) sorted() []Mod {
	out := m.grouped()
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (m *Modules) Init(c *telegram.Client) {
	c.On("callback:help_", func(cb *telegram.CallbackQuery) error {
		data := strings.TrimPrefix(cb.DataString(), "help_")
		if data == "back" {
			return nil
		}
		page := 0
		if i := strings.LastIndexByte(data, ':'); i > 0 {
			page, _ = strconv.Atoi(data[i+1:])
			data = data[:i]
		}
		mod, ok := m.find(data)
		if !ok {
			cb.Answer("Module not found")
			return nil
		}
		return showHelpPage(cb, mod, page)
	})
}

var Mods = Modules{}

func helpPages(help string) []string {
	if len(help) <= helpPageLimit {
		return []string{help}
	}
	var pages []string
	var cur strings.Builder
	for _, line := range strings.Split(help, "\n") {
		if cur.Len() > 0 && cur.Len()+len(line)+1 > helpPageLimit {
			pages = append(pages, strings.TrimRight(cur.String(), "\n"))
			cur.Reset()
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
	}
	if cur.Len() > 0 {
		pages = append(pages, strings.TrimRight(cur.String(), "\n"))
	}
	return pages
}

func showHelpPage(cb *telegram.CallbackQuery, mod Mod, page int) error {
	pages := helpPages(mod.Help)
	page = max(0, min(page, len(pages)-1))
	b := telegram.Button
	kb := telegram.NewKeyboard()
	key := strings.ToLower(mod.Name)
	if len(pages) > 1 {
		var nav []telegram.KeyboardInlineButton
		if page > 0 {
			nav = append(nav, b.Data("‹ Prev", fmt.Sprintf("help_%s:%d", key, page-1)))
		}
		nav = append(nav, b.Data(fmt.Sprintf("%d/%d", page+1, len(pages)), fmt.Sprintf("help_%s:%d", key, page)))
		if page < len(pages)-1 {
			nav = append(nav, b.Data("Next ›", fmt.Sprintf("help_%s:%d", key, page+1)))
		}
		kb.AddRow(nav...)
	}
	kb.AddRow(b.Data("Back to Menu", "help_back"))
	cb.Answer("")
	_, err := cb.Edit(pages[page], &telegram.SendOptions{ReplyMarkup: kb.Build()})
	return err
}

func helpMenu() (string, *telegram.ReplyInlineMarkup) {
	b := telegram.Button
	mods := Mods.sorted()
	buttons := make([]telegram.KeyboardInlineButton, 0, len(mods))
	for _, v := range mods {
		buttons = append(buttons, b.Data(v.Name, "help_"+strings.ToLower(v.Name)))
	}
	text := fmt.Sprintf(`<b>Julia Bot</b>
<i>A feature-rich Telegram bot built with gogram</i>

Select a module below to view its commands and usage, or send <code>/help name</code>.

<b>Available Modules:</b> %d`, len(mods))
	markup := telegram.NewKeyboard().NewColumn(3, buttons...).Build()
	return text, markup
}

func HelpHandle(m *telegram.NewMessage) error {
	if args := strings.TrimSpace(m.Args()); args != "" {
		mod, ok := Mods.find(args)
		if !ok {
			m.Reply("Module not found. Use /help to see all available modules.")
			return nil
		}
		for _, page := range helpPages(mod.Help) {
			m.Reply(page)
		}
		return nil
	}

	if !m.IsPrivate() {
		me := m.Client.Me()
		if me == nil || me.Username == "" {
			m.Reply("Use /help in private chat for detailed help.")
			return nil
		}
		m.Reply("Use /help in private chat for detailed help.",
			&telegram.SendOptions{
				ReplyMarkup: telegram.NewKeyboard().AddRow(telegram.Button.URL("Open Private Chat", "t.me/"+me.Username+"?start=help")).Build(),
			})
		return nil
	}

	text, markup := helpMenu()
	m.Reply(text, &telegram.SendOptions{ReplyMarkup: markup})
	return nil
}

func HelpModuleCallback(name, help string) func(*telegram.CallbackQuery) error {
	return func(c *telegram.CallbackQuery) error {
		return showHelpPage(c, Mod{Name: name, Help: help}, 0)
	}
}

func HelpBackCallback(c *telegram.CallbackQuery) error {
	text, markup := helpMenu()
	c.Answer("")
	_, err := c.Edit(text, &telegram.SendOptions{ReplyMarkup: markup})
	return err
}
