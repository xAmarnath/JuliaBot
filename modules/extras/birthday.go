package extras

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"main/modules/db"

	tg "github.com/xAmarnath/gogram/telegram"

	modules "main/modules"

	"main/internal/mongostore"
)

type birthdayEntry struct {
	UserID     int64  `json:"user_id"`
	Day        int    `json:"day"`
	Month      int    `json:"month"`
	Year       int    `json:"year"`
	LastChatID int64  `json:"last_chat_id"`
	Name       string `json:"name"`
	LastSent   string `json:"last_sent"`
}

const birthdayBucket = "birthdays"

// bdayCache mirrors the birthdays bucket so the per-message tracker never hits the DB
// unless a birthday user's active chat actually changes.
var (
	bdayCache      = map[int64]*birthdayEntry{}
	bdayLoaded     bool
	bdayLastTry    time.Time
	bdayMu         sync.Mutex
	bdayDateSplitR = strings.NewReplacer("/", "-", ".", "-", " ", "-")
)

func bdayEnsureLoaded() bool {
	bdayMu.Lock()
	if bdayLoaded || time.Since(bdayLastTry) < time.Minute {
		ok := bdayLoaded
		bdayMu.Unlock()
		return ok
	}
	bdayLastTry = time.Now()
	bdayMu.Unlock()

	entries, err := listAllBirthdays()
	if err != nil {
		return false
	}
	bdayMu.Lock()
	defer bdayMu.Unlock()
	if !bdayLoaded {
		for _, e := range entries {
			bdayCache[e.UserID] = e
		}
		bdayLoaded = true
	}
	return true
}

func parseBirthdayDate(s string) (int, int, int, error) {
	s = bdayDateSplitR.Replace(strings.TrimSpace(s))
	parts := strings.Split(s, "-")
	if len(parts) != 2 && len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid format")
	}
	day, err := strconv.Atoi(parts[0])
	if err != nil || day < 1 || day > 31 {
		return 0, 0, 0, fmt.Errorf("invalid day")
	}
	month, err := strconv.Atoi(parts[1])
	if err != nil || month < 1 || month > 12 {
		return 0, 0, 0, fmt.Errorf("invalid month")
	}
	year := 0
	if len(parts) == 3 {
		year, err = strconv.Atoi(parts[2])
		if err != nil || year < 1900 || year > 2100 {
			return 0, 0, 0, fmt.Errorf("invalid year")
		}
	}
	if _, err := time.Parse("2-1-2006", fmt.Sprintf("%d-%d-%d", day, month, 2000)); err != nil {
		return 0, 0, 0, fmt.Errorf("invalid date")
	}
	return day, month, year, nil
}

func saveBirthday(entry *birthdayEntry) error {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return fmt.Errorf("db error")
	}
	err = database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(birthdayBucket))
		if err != nil {
			return err
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(strconv.FormatInt(entry.UserID, 10)), data)
	})
	if err == nil {
		cp := *entry
		bdayMu.Lock()
		bdayCache[entry.UserID] = &cp
		bdayMu.Unlock()
	}
	return err
}

func loadBirthday(userID int64) (*birthdayEntry, error) {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return nil, fmt.Errorf("db error")
	}
	var entry *birthdayEntry
	err = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(birthdayBucket))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(strconv.FormatInt(userID, 10)))
		if v == nil {
			return nil
		}
		var e birthdayEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		entry = &e
		return nil
	})
	return entry, err
}

func deleteBirthday(userID int64) error {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return fmt.Errorf("db error")
	}
	err = database.Update(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(birthdayBucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(strconv.FormatInt(userID, 10)))
	})
	if err == nil {
		bdayMu.Lock()
		delete(bdayCache, userID)
		bdayMu.Unlock()
	}
	return err
}

func listAllBirthdays() ([]*birthdayEntry, error) {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return nil, fmt.Errorf("db error")
	}
	var entries []*birthdayEntry
	err = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(birthdayBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var e birthdayEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return nil
			}
			entries = append(entries, &e)
			return nil
		})
	})
	return entries, err
}

func updateLastActiveChat(userID, chatID int64, name string) {
	if !bdayEnsureLoaded() {
		return
	}
	bdayMu.Lock()
	cur, ok := bdayCache[userID]
	if !ok || (cur.LastChatID == chatID && (name == "" || cur.Name == name)) {
		bdayMu.Unlock()
		return
	}
	entry := *cur
	bdayMu.Unlock()
	entry.LastChatID = chatID
	if name != "" {
		entry.Name = name
	}
	_ = saveBirthday(&entry)
}

func birthdayOrdinal(n int) string {
	suffix := "th"
	if n%100 < 11 || n%100 > 13 {
		switch n % 10 {
		case 1:
			suffix = "st"
		case 2:
			suffix = "nd"
		case 3:
			suffix = "rd"
		}
	}
	return strconv.Itoa(n) + suffix
}

// birthdayIsToday also wishes 29 Feb birthdays on 28 Feb in non-leap years.
func birthdayIsToday(day, month int, now time.Time) bool {
	if day == now.Day() && month == int(now.Month()) {
		return true
	}
	if day == 29 && month == 2 && now.Month() == time.February && now.Day() == 28 {
		return time.Date(now.Year(), time.February, 29, 0, 0, 0, 0, time.UTC).Month() != time.February
	}
	return false
}

func daysUntilBirthday(day, month int, now time.Time) int {
	year := now.Year()
	next := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if next.Before(today) {
		next = time.Date(year+1, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	}
	return int(next.Sub(today).Hours() / 24)
}

func formatBirthdayDate(day, month, year int) string {
	monthName := time.Month(month).String()
	if year > 0 {
		return fmt.Sprintf("%d %s %d", day, monthName, year)
	}
	return fmt.Sprintf("%d %s", day, monthName)
}

func birthdaySet(m *tg.NewMessage, day, month, year int) {
	entry := &birthdayEntry{
		UserID:     m.SenderID(),
		Day:        day,
		Month:      month,
		Year:       year,
		LastChatID: m.ChannelID(),
		Name:       m.Sender.FirstName,
	}
	if old, _ := loadBirthday(m.SenderID()); old != nil {
		entry.LastSent = old.LastSent
		if m.IsPrivate() && old.LastChatID != 0 {
			entry.LastChatID = old.LastChatID
		}
	}
	if err := saveBirthday(entry); err != nil {
		m.Reply("<b>Failed to save birthday.</b>")
		return
	}
	m.Reply(fmt.Sprintf("<b>Birthday saved:</b> %s", formatBirthdayDate(day, month, year)))
}

func BirthdayHandler(m *tg.NewMessage) error {
	if m.Sender == nil {
		m.Reply("<b>Birthdays can only be set from a user account.</b>")
		return nil
	}
	args := strings.TrimSpace(m.Args())
	if args == "" {
		entry, _ := loadBirthday(m.SenderID())
		if entry == nil {
			m.Reply("<b>Usage:</b>\n" +
				"<code>/bday set DD-MM</code> or <code>/bday set DD-MM-YYYY</code>\n" +
				"<code>/bday clear</code>\n" +
				"<code>/bday check [@user]</code>")
			return nil
		}
		m.Reply(fmt.Sprintf("<b>Your birthday:</b> %s", formatBirthdayDate(entry.Day, entry.Month, entry.Year)))
		return nil
	}

	parts := strings.SplitN(args, " ", 2)
	sub := strings.ToLower(parts[0])
	rest := ""
	if len(parts) > 1 {
		rest = strings.TrimSpace(parts[1])
	}

	switch sub {
	case "set":
		if rest == "" {
			m.Reply("<b>Usage:</b> <code>/bday set DD-MM</code> or <code>/bday set DD-MM-YYYY</code>")
			return nil
		}
		day, month, year, err := parseBirthdayDate(rest)
		if err != nil {
			m.Reply("<b>Invalid date.</b> Use <code>DD-MM</code> or <code>DD-MM-YYYY</code>.")
			return nil
		}
		birthdaySet(m, day, month, year)
		return nil

	case "clear", "remove", "delete":
		entry, _ := loadBirthday(m.SenderID())
		if entry == nil {
			m.Reply("<b>No birthday set.</b>")
			return nil
		}
		if err := deleteBirthday(m.SenderID()); err != nil {
			m.Reply("<b>Failed to clear birthday.</b>")
			return nil
		}
		m.Reply("<b>Birthday cleared.</b>")
		return nil

	case "check":
		targetID := m.SenderID()
		targetName := m.Sender.FirstName
		if m.IsReply() {
			r, err := m.GetReplyMessage()
			if err != nil || r == nil || r.SenderID() == 0 {
				m.Reply("<b>Couldn't read the replied-to user.</b>")
				return nil
			}
			targetID = r.SenderID()
			if r.Sender != nil {
				targetName = r.Sender.FirstName
			}
		} else if rest != "" {
			peer, err := m.Client.ResolvePeer(rest)
			if err != nil {
				m.Reply(fmt.Sprintf("<b>User not found:</b> <code>%s</code>", html.EscapeString(rest)))
				return nil
			}
			if _, ok := peer.(*tg.InputPeerUser); !ok {
				m.Reply("<b>That's not a user.</b>")
				return nil
			}
			targetID = m.Client.GetPeerID(peer)
			targetName = rest
			if u, _ := m.Client.GetUser(targetID); u != nil && u.FirstName != "" {
				targetName = u.FirstName
			}
		}
		entry, _ := loadBirthday(targetID)
		if entry == nil {
			m.Reply(fmt.Sprintf("<b>%s</b> has not set a birthday.", html.EscapeString(targetName)))
			return nil
		}
		days := daysUntilBirthday(entry.Day, entry.Month, time.Now().UTC())
		dateStr := formatBirthdayDate(entry.Day, entry.Month, entry.Year)
		if days == 0 {
			m.Reply(fmt.Sprintf("<b>Today is %s's birthday!</b> (%s)", html.EscapeString(targetName), dateStr))
		} else {
			m.Reply(fmt.Sprintf("<b>%s's birthday:</b> %s\n<b>In:</b> %d day(s)", html.EscapeString(targetName), dateStr, days))
		}
		return nil

	default:
		day, month, year, err := parseBirthdayDate(args)
		if err == nil {
			birthdaySet(m, day, month, year)
			return nil
		}
		m.Reply("<b>Unknown subcommand.</b>\n" +
			"Use <code>/bday set DD-MM</code>, <code>/bday clear</code>, or <code>/bday check [@user]</code>")
		return nil
	}
}

func UpcomingBirthdaysHandler(m *tg.NewMessage) error {
	entries, err := listAllBirthdays()
	if err != nil {
		m.Reply("<b>Couldn't load birthdays.</b> Try again later.")
		return nil
	}
	// In groups, only list members whose last active chat is this one.
	if !m.IsPrivate() {
		here := entries[:0]
		for _, e := range entries {
			if e.LastChatID == m.ChannelID() || e.LastChatID == m.ChatID() {
				here = append(here, e)
			}
		}
		entries = here
	}
	if len(entries) == 0 {
		m.Reply("<b>No birthdays saved yet.</b>")
		return nil
	}
	now := time.Now().UTC()
	sort.Slice(entries, func(i, j int) bool {
		return daysUntilBirthday(entries[i].Day, entries[i].Month, now) < daysUntilBirthday(entries[j].Day, entries[j].Month, now)
	})

	var sb strings.Builder
	sb.WriteString("<b>Upcoming Birthdays</b>\n")
	sb.WriteString("━━━━━━━━━━━━━━━━\n")
	limit := 5
	if len(entries) < limit {
		limit = len(entries)
	}
	for i := 0; i < limit; i++ {
		e := entries[i]
		days := daysUntilBirthday(e.Day, e.Month, now)
		name := e.Name
		if name == "" {
			name = strconv.FormatInt(e.UserID, 10)
		}
		when := fmt.Sprintf("in %d day(s)", days)
		switch days {
		case 0:
			when = "today"
		case 1:
			when = "tomorrow"
		}
		sb.WriteString(fmt.Sprintf(" • <b>%s</b> — %s (%s)\n", html.EscapeString(name), formatBirthdayDate(e.Day, e.Month, e.Year), when))
	}
	m.Reply(sb.String())
	return nil
}

func BirthdayActivityTracker(m *tg.NewMessage) error {
	if m == nil || m.Message == nil || m.IsPrivate() || m.Sender == nil || m.Sender.Bot {
		return nil
	}
	updateLastActiveChat(m.Sender.ID, m.ChannelID(), m.Sender.FirstName)
	return nil
}

func birthdayTicker() {
	// Dynos restart daily; catch up on today's wishes in case 09:00 was missed. LastSent prevents duplicates.
	time.Sleep(2 * time.Minute)
	if time.Now().UTC().Hour() >= 9 {
		runBirthdayCheck()
	}
	for {
		now := time.Now().UTC()
		next := time.Date(now.Year(), now.Month(), now.Day(), 9, 0, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		time.Sleep(time.Until(next))
		runBirthdayCheck()
	}
}

func runBirthdayCheck() {
	if modules.Client == nil {
		return
	}
	entries, err := listAllBirthdays()
	if err != nil || len(entries) == 0 {
		return
	}
	now := time.Now().UTC()
	todayKey := now.Format("2006-01-02")
	for _, e := range entries {
		if !birthdayIsToday(e.Day, e.Month, now) {
			continue
		}
		if e.LastSent == todayKey {
			continue
		}
		if e.LastChatID == 0 {
			continue
		}
		name := e.Name
		if name == "" {
			name = "friend"
		}
		mention := fmt.Sprintf("<a href='tg://user?id=%d'>%s</a>", e.UserID, html.EscapeString(name))
		text := fmt.Sprintf("🎂 Happy birthday %s!", mention)
		if e.Year > 0 {
			age := now.Year() - e.Year
			if age > 0 && age < 130 {
				text = fmt.Sprintf("🎂 Happy %s birthday %s!", birthdayOrdinal(age), mention)
			}
		}
		_, sendErr := modules.Client.SendMessage(e.LastChatID, text)
		if sendErr == nil {
			e.LastSent = todayKey
			_ = saveBirthday(e)
		}
	}
}

func registerBirthdayHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:bday", BirthdayHandler)
	modules.OnCommand(c, "cmd:birthday", BirthdayHandler)
	modules.OnCommand(c, "cmd:upcoming", UpcomingBirthdaysHandler)
	c.On(tg.OnNewMessage, BirthdayActivityTracker)
	go birthdayTicker()
}

func init() {
	modules.QueueHandlerRegistration(registerBirthdayHandlers)

	modules.Mods.AddModule("Birthday", `<b>Birthday Module</b>

<b>Commands:</b>
 • <code>/bday</code> - Show your saved birthday
 • <code>/bday set DD-MM</code> or <code>DD-MM-YYYY</code> - Save your birthday (<code>/</code> or <code>.</code> also work)
 • <code>/bday clear</code> - Remove your birthday
 • <code>/bday check [@user]</code> - Check a birthday (or reply to someone)
 • <code>/upcoming</code> - Next 5 birthdays (in a group: members active here)
 • <code>/birthday</code> - Alias for /bday

<b>Example:</b> <code>/bday set 14-02-1999</code>

<i>Wishes are sent at 09:00 UTC to the last group you were active in.</i>`)
}
