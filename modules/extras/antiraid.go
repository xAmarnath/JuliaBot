package extras

import (
	"encoding/json"
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

type AntiraidSettings struct {
	Enabled     bool  `json:"enabled"`
	Threshold   int   `json:"threshold"`
	WindowSec   int   `json:"window_sec"`
	CooldownMin int   `json:"cooldown_min"`
	LockedUntil int64 `json:"locked_until"`
}

type antiraidJoin struct {
	at     time.Time
	userID int64
}

var (
	antiraidJoinsMu sync.Mutex
	antiraidJoins   = make(map[int64][]antiraidJoin)

	antiraidCfgMu sync.RWMutex
	antiraidCfg   = make(map[int64]AntiraidSettings)
)

func defaultAntiraidSettings() *AntiraidSettings {
	return &AntiraidSettings{Threshold: 5, WindowSec: 10, CooldownMin: 5}
}

func (s *AntiraidSettings) normalize() {
	if s.Threshold < 2 {
		s.Threshold = 5
	}
	if s.WindowSec < 1 {
		s.WindowSec = 10
	}
	if s.CooldownMin < 1 {
		s.CooldownMin = 5
	}
}

func getAntiraidSettings(chatID int64) *AntiraidSettings {
	antiraidCfgMu.RLock()
	if v, ok := antiraidCfg[chatID]; ok {
		antiraidCfgMu.RUnlock()
		return &v
	}
	antiraidCfgMu.RUnlock()

	s := defaultAntiraidSettings()
	database, err := db.GetDB()
	if err != nil || database == nil {
		return s
	}
	if err := database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte("antiraid"))
		if b == nil {
			return nil
		}
		if data := b.Get([]byte(strconv.FormatInt(chatID, 10))); data != nil {
			_ = json.Unmarshal(data, s)
		}
		return nil
	}); err != nil {
		return s
	}
	s.normalize()
	antiraidCfgMu.Lock()
	antiraidCfg[chatID] = *s
	antiraidCfgMu.Unlock()
	return s
}

func saveAntiraidSettings(chatID int64, s *AntiraidSettings) error {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return fmt.Errorf("db unavailable")
	}
	err = database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("antiraid"))
		if err != nil {
			return err
		}
		data, err := json.Marshal(s)
		if err != nil {
			return err
		}
		return b.Put([]byte(strconv.FormatInt(chatID, 10)), data)
	})
	if err != nil {
		return err
	}
	antiraidCfgMu.Lock()
	antiraidCfg[chatID] = *s
	antiraidCfgMu.Unlock()
	return nil
}

// antiraidRecordJoin appends a join and reports whether the threshold is reached; on trip it returns
// every user that joined inside the window and resets the counter.
func antiraidRecordJoin(chatID, userID int64, now time.Time, threshold int, window time.Duration) (bool, []int64) {
	antiraidJoinsMu.Lock()
	defer antiraidJoinsMu.Unlock()
	cutoff := now.Add(-window)
	joins := antiraidJoins[chatID]
	pruned := joins[:0]
	for _, j := range joins {
		if j.at.After(cutoff) {
			pruned = append(pruned, j)
		}
	}
	pruned = append(pruned, antiraidJoin{at: now, userID: userID})
	if len(pruned) < threshold {
		antiraidJoins[chatID] = pruned
		return false, nil
	}
	seen := make(map[int64]bool, len(pruned))
	var users []int64
	for _, j := range pruned {
		if !seen[j.userID] {
			seen[j.userID] = true
			users = append(users, j.userID)
		}
	}
	delete(antiraidJoins, chatID)
	return true, users
}

func antiraidStatusText(s *AntiraidSettings) string {
	state := "off"
	if s.Enabled {
		state = "on"
	}
	lock := "inactive"
	if s.LockedUntil > time.Now().Unix() {
		lock = fmt.Sprintf("<b>active</b> (%s left)", time.Until(time.Unix(s.LockedUntil, 0)).Round(time.Second))
	}
	return fmt.Sprintf(`<b>Antiraid</b>

Status: <b>%s</b>
Threshold: <b>%d joins / %d seconds</b>
Lockdown length: <b>%d minutes</b>
Lockdown: %s

<b>Usage:</b>
<code>/antiraid on|off|status</code>
<code>/antiraid threshold &lt;joins&gt; &lt;seconds&gt;</code>
<code>/antiraid cooldown &lt;minutes&gt;</code>
<code>/antiraid end</code>`, state, s.Threshold, s.WindowSec, s.CooldownMin, lock)
}

func AntiraidHandler(m *tg.NewMessage) error {
	if !modules.RequireGroup(m) {
		return nil
	}
	if !modules.SenderHasRight(m, "ban") {
		m.Reply("You need the <b>Ban Users</b> admin right to manage antiraid.")
		return nil
	}

	args := strings.Fields(modules.CommandArgs(m.Text()))
	settings := getAntiraidSettings(m.ChatID())
	if len(args) == 0 {
		m.Reply(antiraidStatusText(settings))
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "on", "enable", "yes", "1":
		if m.ChannelID() > -1000000000000 {
			m.Reply("Antiraid needs a supergroup; basic groups don't send me join events.")
			return nil
		}
		settings.Enabled = true
		if err := saveAntiraidSettings(m.ChatID(), settings); err != nil {
			m.Reply("I couldn't save that setting. Please try again.")
			return nil
		}
		msg := fmt.Sprintf("Antiraid <b>enabled</b>.\nThreshold: %d joins in %d seconds\nLockdown length: %d minutes",
			settings.Threshold, settings.WindowSec, settings.CooldownMin)
		if !modules.BotHasRight(m.Client, m.ChannelID(), "ban") {
			msg += "\n\n<i>Note: I need the Ban Users right to remove raiders.</i>"
		}
		m.Reply(msg)
	case "off", "disable", "no", "0":
		settings.Enabled = false
		settings.LockedUntil = 0
		if err := saveAntiraidSettings(m.ChatID(), settings); err != nil {
			m.Reply("I couldn't save that setting. Please try again.")
			return nil
		}
		antiraidJoinsMu.Lock()
		delete(antiraidJoins, m.ChatID())
		antiraidJoinsMu.Unlock()
		m.Reply("Antiraid <b>disabled</b>.")
	case "status":
		m.Reply(antiraidStatusText(settings))
	case "end", "stop", "lift", "unlock":
		if settings.LockedUntil <= time.Now().Unix() {
			m.Reply("There's no active lockdown.")
			return nil
		}
		settings.LockedUntil = 0
		if err := saveAntiraidSettings(m.ChatID(), settings); err != nil {
			m.Reply("I couldn't save that setting. Please try again.")
			return nil
		}
		m.Reply("Lockdown lifted. New members can join again.")
	case "threshold":
		if len(args) < 3 {
			m.Reply("Usage: <code>/antiraid threshold &lt;joins&gt; &lt;seconds&gt;</code>\nExample: <code>/antiraid threshold 8 15</code>")
			return nil
		}
		joins, err1 := strconv.Atoi(args[1])
		secs, err2 := strconv.Atoi(args[2])
		if err1 != nil || err2 != nil || joins < 2 || joins > 100 || secs < 1 || secs > 600 {
			m.Reply("Invalid threshold. Joins must be 2-100 and seconds 1-600.")
			return nil
		}
		settings.Threshold = joins
		settings.WindowSec = secs
		if err := saveAntiraidSettings(m.ChatID(), settings); err != nil {
			m.Reply("I couldn't save that setting. Please try again.")
			return nil
		}
		m.Reply(fmt.Sprintf("Antiraid threshold set to <b>%d joins / %d seconds</b>.", joins, secs))
	case "cooldown":
		if len(args) < 2 {
			m.Reply("Usage: <code>/antiraid cooldown &lt;minutes&gt;</code>")
			return nil
		}
		mins, err := strconv.Atoi(args[1])
		if err != nil || mins < 1 || mins > 1440 {
			m.Reply("Invalid cooldown. It must be between 1 and 1440 minutes.")
			return nil
		}
		settings.CooldownMin = mins
		if err := saveAntiraidSettings(m.ChatID(), settings); err != nil {
			m.Reply("I couldn't save that setting. Please try again.")
			return nil
		}
		m.Reply(fmt.Sprintf("Lockdown length set to <b>%d minutes</b>.", mins))
	default:
		m.Reply("Usage: <code>/antiraid on|off|status|end</code>, <code>/antiraid threshold &lt;joins&gt; &lt;seconds&gt;</code>, <code>/antiraid cooldown &lt;minutes&gt;</code>")
	}
	return nil
}

func antiraidRemove(c *tg.Client, chat int64, userIDs []int64) {
	me := c.Me()
	for _, uid := range userIDs {
		if uid == 0 || (me != nil && uid == me.ID) || modules.IsChatAdmin(c, chat, uid) {
			continue
		}
		peer, err := c.ResolvePeer(uid)
		if err != nil {
			continue
		}
		_ = modules.KickMember(c, chat, peer)
	}
}

func AntiraidParticipantHandler(p *tg.ParticipantUpdate) error {
	if p == nil || p.User == nil || p.Channel == nil {
		return nil
	}
	if !p.IsJoined() && !p.IsAdded() {
		return nil
	}

	chatID := p.ChatID()
	settings := getAntiraidSettings(chatID)
	if !settings.Enabled {
		return nil
	}
	chat := p.ChannelID()
	user := p.User.ID
	// Members added by an admin are trusted.
	if actor := p.ActorID(); actor != 0 && actor != user && modules.IsChatAdmin(p.Client, chat, actor) {
		return nil
	}

	now := time.Now()
	if settings.LockedUntil > now.Unix() {
		go antiraidRemove(p.Client, chat, []int64{user})
		return nil
	}

	tripped, users := antiraidRecordJoin(chatID, user, now, settings.Threshold, time.Duration(settings.WindowSec)*time.Second)
	if !tripped {
		return nil
	}
	settings.LockedUntil = now.Add(time.Duration(settings.CooldownMin) * time.Minute).Unix()
	_ = saveAntiraidSettings(chatID, settings)

	_, _ = p.Client.SendMessage(chat, fmt.Sprintf(
		"<b>Antiraid triggered</b>\n%d joins within %d seconds. Lockdown for %d minute(s): recent and new joiners are being removed.\nAdmins can end it early with <code>/antiraid end</code>.",
		len(users), settings.WindowSec, settings.CooldownMin))
	go antiraidRemove(p.Client, chat, users)
	return nil
}

func registerAntiraidHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:antiraid", AntiraidHandler)
	c.On(tg.OnParticipant, AntiraidParticipantHandler)
}

func init() {
	modules.QueueHandlerRegistration(registerAntiraidHandlers)

	modules.Mods.AddModule("Antiraid", `<b>Antiraid</b>

Detects join floods. When too many people join in a short window, the bot starts a lockdown: everyone who joined in that window is removed, and anyone joining during the lockdown is removed too. Removed users are kicked, not banned, so real members can rejoin later. Users added by an admin are never removed.

<b>Commands</b> (need the Ban Users right):
 - <code>/antiraid</code> or <code>/antiraid status</code> - Show settings and lockdown state
 - <code>/antiraid on</code> / <code>/antiraid off</code> - Enable or disable
 - <code>/antiraid threshold &lt;joins&gt; &lt;seconds&gt;</code> - Trigger level (joins 2-100, seconds 1-600)
 - <code>/antiraid cooldown &lt;minutes&gt;</code> - Lockdown length (1-1440)
 - <code>/antiraid end</code> - Lift an active lockdown early

<b>Examples:</b>
 <code>/antiraid threshold 8 15</code> - lock down when 8 people join within 15 seconds
 <code>/antiraid cooldown 30</code> - keep the lockdown for 30 minutes

<b>Defaults:</b> 5 joins in 10 seconds, 5 minute lockdown.
<b>Notes:</b> Supergroups only. I need the Ban Users right.`)
}
