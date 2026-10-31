package extras

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"main/modules/db"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fogleman/gg"
	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
	modules "main/modules"
)

func serializeButtons(buttons [][]tg.KeyboardInlineButton) string {
	var lines []string
	for _, row := range buttons {
		var rowParts []string
		for i, btn := range row {
			switch b := btn.Type.(type) {
			case *tg.InlineButtonTypeURL:
				if i > 0 {
					rowParts = append(rowParts, fmt.Sprintf("[same:%s](%s)", btn.Text, b.URL))
				} else {
					rowParts = append(rowParts, fmt.Sprintf("[%s](%s)", btn.Text, b.URL))
				}
			case *tg.InlineButtonTypeCallback:
				data := string(b.Data)
				if data == "rules_show" {
					data = "rules"
				}
				if i > 0 {
					rowParts = append(rowParts, fmt.Sprintf("[same:%s](%s)", btn.Text, data))
				} else {
					rowParts = append(rowParts, fmt.Sprintf("[%s](%s)", btn.Text, data))
				}
			}
		}
		lines = append(lines, strings.Join(rowParts, " "))
	}
	return strings.Join(lines, "\n")
}

var defaultJoinFilterEmoji = []string{
	"🏳️‍🌈", "🏳‍🌈", "🏳️‍⚧️", "🏳‍⚧",
	"🌈",
}

type JoinFilterConfig struct {
	Enabled  bool     `json:"enabled"`
	Emoji    []string `json:"emoji"`
	Patterns []string `json:"patterns"`
}

const joinFilterBucket = "joinfilter_cfg"

func getJoinFilterConfig(chatID int64) *JoinFilterConfig {
	cfg := &JoinFilterConfig{Enabled: false, Emoji: append([]string{}, defaultJoinFilterEmoji...)}
	database, err := db.GetDB()
	if err != nil || database == nil {
		return cfg
	}
	_ = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(joinFilterBucket))
		if b == nil {
			return nil
		}
		data := b.Get([]byte(strconv.FormatInt(chatID, 10)))
		if data == nil {
			return nil
		}
		_ = json.Unmarshal(data, cfg)
		return nil
	})
	return cfg
}

func saveJoinFilterConfig(chatID int64, cfg *JoinFilterConfig) error {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return fmt.Errorf("db unavailable")
	}
	return database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(joinFilterBucket))
		if err != nil {
			return err
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return b.Put([]byte(strconv.FormatInt(chatID, 10)), data)
	})
}

func joinFilterDisplayName(user *tg.UserObj) string {
	if user == nil {
		return ""
	}
	name := strings.TrimSpace(user.FirstName + " " + user.LastName)
	if name == "" {
		name = user.Username
	}
	return name
}

func joinFilterMatch(chatID int64, user *tg.UserObj) (string, bool) {
	cfg := getJoinFilterConfig(chatID)
	if !cfg.Enabled {
		return "", false
	}
	name := joinFilterDisplayName(user)
	if name == "" {
		return "", false
	}
	for _, e := range cfg.Emoji {
		if e != "" && strings.Contains(name, e) {
			return "name contains blocklisted emoji: " + e, true
		}
	}
	for _, p := range cfg.Patterns {
		re, err := modules.ValidateUserRegex(p)
		if err != nil {
			continue
		}
		if re.MatchString(name) {
			return "name matches blocked pattern: " + p, true
		}
	}
	return "", false
}

func joinFilterBan(client *tg.Client, chatID int64, user *tg.UserObj, reason string) {
	peer, err := client.ResolvePeer(user.ID)
	if err != nil || peer == nil {
		return
	}
	if _, err := client.EditBanned(chatID, peer, &tg.BannedOptions{Ban: true}); err != nil {
		log.Printf("join filter removal: %v", err)
		return
	}
	_, _ = client.SendMessage(chatID, fmt.Sprintf(
		"Removed %s on join — %s.",
		html.EscapeString(joinFilterDisplayName(user)),
		html.EscapeString(reason),
	))
}

func JoinFilterCommandHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("Join filter is only available in groups.")
		return nil
	}
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "ban") {
		m.Reply("You need Ban Users permission to manage the join filter.")
		return nil
	}

	args := strings.Fields(m.Args())
	cfg := getJoinFilterConfig(m.ChatID())

	if len(args) == 0 {
		status := "off"
		if cfg.Enabled {
			status = "on"
		}
		m.Reply(fmt.Sprintf(`<b>Join Filter</b>

State: <b>%s</b>
Emoji entries: <b>%d</b>
Regex patterns: <b>%d</b>

<b>Usage:</b>
/joinfilter on|off
/joinfilter list
/joinfilter addemoji &lt;emoji&gt; — block joiners whose name contains it
/joinfilter rmemoji &lt;emoji&gt;
/joinfilter addregex &lt;pattern&gt; — case-insensitive; wrap in / /
/joinfilter rmregex &lt;pattern&gt;
/joinfilter reset — restore defaults (pride flags)

Matches auto-ban new joiners before they see captcha or welcome.`, status, len(cfg.Emoji), len(cfg.Patterns)))
		return nil
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "on", "enable", "yes", "1":
		cfg.Enabled = true
	case "off", "disable", "no", "0":
		lock := &captchaSetupLocks[uint64(m.ChatID())%64]
		lock.Lock()
		defer lock.Unlock()
		cfg.Enabled = false
	case "list":
		var b strings.Builder
		b.WriteString("<b>Join Filter entries</b>\n\n")
		b.WriteString("<b>Emoji blocklist:</b>\n")
		if len(cfg.Emoji) == 0 {
			b.WriteString("(empty)\n")
		}
		for _, e := range cfg.Emoji {
			b.WriteString(html.EscapeString(e))
			b.WriteString("\n")
		}
		b.WriteString("\n<b>Regex patterns:</b>\n")
		if len(cfg.Patterns) == 0 {
			b.WriteString("(empty)\n")
		}
		for _, p := range cfg.Patterns {
			b.WriteString("<code>")
			b.WriteString(html.EscapeString(p))
			b.WriteString("</code>\n")
		}
		m.Reply(b.String())
		return nil
	case "addemoji":
		if len(args) < 2 {
			m.Reply("Usage: /joinfilter addemoji &lt;emoji&gt;")
			return nil
		}
		emoji := strings.Join(args[1:], "")
		for _, e := range cfg.Emoji {
			if e == emoji {
				m.Reply("Already in list.")
				return nil
			}
		}
		cfg.Emoji = append(cfg.Emoji, emoji)
	case "rmemoji":
		if len(args) < 2 {
			m.Reply("Usage: /joinfilter rmemoji &lt;emoji&gt;")
			return nil
		}
		emoji := strings.Join(args[1:], "")
		out := cfg.Emoji[:0]
		removed := false
		for _, e := range cfg.Emoji {
			if e == emoji {
				removed = true
				continue
			}
			out = append(out, e)
		}
		cfg.Emoji = out
		if !removed {
			m.Reply("Not in list.")
			return nil
		}
	case "addregex":
		if len(args) < 2 {
			m.Reply("Usage: /joinfilter addregex &lt;pattern&gt;")
			return nil
		}
		pattern := strings.Join(args[1:], " ")
		if _, err := modules.ValidateUserRegex(pattern); err != nil {
			m.Reply("Rejected: " + html.EscapeString(err.Error()))
			return nil
		}
		for _, p := range cfg.Patterns {
			if p == pattern {
				m.Reply("Already in list.")
				return nil
			}
		}
		cfg.Patterns = append(cfg.Patterns, pattern)
	case "rmregex":
		if len(args) < 2 {
			m.Reply("Usage: /joinfilter rmregex &lt;pattern&gt;")
			return nil
		}
		pattern := strings.Join(args[1:], " ")
		out := cfg.Patterns[:0]
		removed := false
		for _, p := range cfg.Patterns {
			if p == pattern {
				removed = true
				continue
			}
			out = append(out, p)
		}
		cfg.Patterns = out
		if !removed {
			m.Reply("Not in list.")
			return nil
		}
	case "reset":
		cfg.Emoji = append([]string{}, defaultJoinFilterEmoji...)
		cfg.Patterns = nil
	default:
		m.Reply("Usage: /joinfilter on|off|list|addemoji|rmemoji|addregex|rmregex|reset")
		return nil
	}

	if err := saveJoinFilterConfig(m.ChatID(), cfg); err != nil {
		m.Reply("Failed to save join filter config.")
		return nil
	}
	m.Reply("Join filter updated.")
	return nil
}

const (
	captchaBucket   = "captcha_cfg"
	captchaTypeBtn  = "button"
	captchaTypeMath = "math"
	captchaTypeText = "text"
	captchaPrefix   = "cap:"
)

type CaptchaConfig struct {
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
	Timeout int    `json:"timeout"`
}

type captchaState struct {
	Restricted bool
	Finished   atomic.Bool
	Ready      chan struct{}
	UserID     int64
	ChatID     int64
	Type       string
	Answer     string
	MessageID  int32
	Deadline   time.Time
	Cancel     chan struct{}
	UserName   string
	User       *tg.UserObj
}

var captchaStates sync.Map
var captchaSetupLocks [64]sync.Mutex

func captchaStateKey(chatID, userID int64) string {
	return fmt.Sprintf("%d:%d", chatID, userID)
}

func defaultCaptchaConfig() *CaptchaConfig {
	return &CaptchaConfig{Enabled: false, Type: captchaTypeBtn, Timeout: 60}
}

func getCaptchaConfig(chatID int64) *CaptchaConfig {
	cfg := defaultCaptchaConfig()
	database, err := db.GetDB()
	if err != nil || database == nil {
		return cfg
	}
	_ = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(captchaBucket))
		if b == nil {
			return nil
		}
		data := b.Get([]byte(strconv.FormatInt(chatID, 10)))
		if data == nil {
			return nil
		}
		_ = json.Unmarshal(data, cfg)
		return nil
	})
	if cfg.Type != captchaTypeBtn && cfg.Type != captchaTypeMath && cfg.Type != captchaTypeText {
		cfg.Type = captchaTypeBtn
	}
	if cfg.Timeout < 15 || cfg.Timeout > 600 {
		cfg.Timeout = 60
	}
	return cfg
}

func saveCaptchaConfig(chatID int64, cfg *CaptchaConfig) error {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return fmt.Errorf("db unavailable")
	}
	return database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(captchaBucket))
		if err != nil {
			return err
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return b.Put([]byte(strconv.FormatInt(chatID, 10)), data)
	})
}

func CaptchaEnabled(chatID int64) bool {
	return getCaptchaConfig(chatID).Enabled
}

func captchaLoadFont(dc *gg.Context, size float64) {
	name := modules.GetRandomFont()
	candidates := []string{
		"./assets/" + name,
		"assets/" + name,
		"../assets/" + name,
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "assets", name))
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "assets", name),
			filepath.Join(dir, "..", "assets", name),
		)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			if err := dc.LoadFontFace(p, size); err == nil {
				return
			}
		}
	}
}

func captchaDrawNoise(dc *gg.Context, w, h int) {
	for range 1200 {
		x := rand.Float64() * float64(w)
		y := rand.Float64() * float64(h)
		dc.SetRGBA(rand.Float64(), rand.Float64(), rand.Float64(), 0.35)
		dc.DrawPoint(x, y, 1.2)
		dc.Fill()
	}
	for range 8 {
		dc.SetRGBA(rand.Float64(), rand.Float64(), rand.Float64(), 0.45)
		dc.SetLineWidth(1 + rand.Float64()*2)
		dc.DrawLine(
			rand.Float64()*float64(w), rand.Float64()*float64(h),
			rand.Float64()*float64(w), rand.Float64()*float64(h),
		)
		dc.Stroke()
	}
}

func captchaRenderText(text string, w, h int, fontSize float64) (string, error) {
	dc := gg.NewContext(w, h)
	dc.SetRGB(0.95, 0.95, 0.95)
	dc.Clear()

	captchaDrawNoise(dc, w, h)

	captchaLoadFont(dc, fontSize)
	chars := []rune(text)
	if len(chars) == 0 {
		return "", fmt.Errorf("empty text")
	}
	cellW := float64(w) / float64(len(chars)+1)
	for i, ch := range chars {
		dc.Push()
		x := cellW*float64(i+1) + (rand.Float64()-0.5)*6
		y := float64(h)/2 + (rand.Float64()-0.5)*10
		angle := (rand.Float64() - 0.5) * 0.6
		dc.RotateAbout(angle, x, y)
		dc.SetRGB(rand.Float64()*0.4, rand.Float64()*0.4, rand.Float64()*0.4)
		dc.DrawStringAnchored(string(ch), x, y, 0.5, 0.5)
		dc.Pop()
	}

	for range 4 {
		dc.SetRGBA(rand.Float64()*0.6, rand.Float64()*0.6, rand.Float64()*0.6, 0.4)
		dc.SetLineWidth(1.2)
		dc.DrawLine(
			rand.Float64()*float64(w), rand.Float64()*float64(h),
			rand.Float64()*float64(w), rand.Float64()*float64(h),
		)
		dc.Stroke()
	}

	out := filepath.Join(os.TempDir(), fmt.Sprintf("captcha_%d.png", time.Now().UnixNano()))
	if err := dc.SavePNG(out); err != nil {
		return "", err
	}
	return out, nil
}

func captchaRandomString(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func captchaGenMath() (string, string) {
	a := rand.Intn(20) + 1
	b := rand.Intn(20) + 1
	switch rand.Intn(3) {
	case 0:
		return fmt.Sprintf("%d + %d = ?", a, b), strconv.Itoa(a + b)
	case 1:
		if a < b {
			a, b = b, a
		}
		return fmt.Sprintf("%d - %d = ?", a, b), strconv.Itoa(a - b)
	default:
		x := rand.Intn(9) + 2
		y := rand.Intn(9) + 2
		return fmt.Sprintf("%d x %d = ?", x, y), strconv.Itoa(x * y)
	}
}

// Only the state still registered for this join may finish it.
// Keeping it registered during Telegram calls prevents a duplicate challenge.
func claimCaptcha(st *captchaState) bool {
	current, ok := captchaStates.Load(captchaStateKey(st.ChatID, st.UserID))
	if !ok || current != st || !st.Finished.CompareAndSwap(false, true) {
		return false
	}
	close(st.Cancel)
	return true
}
func captchaRestrictUser(c *tg.Client, chatID int64, userID int64, restrict bool) error {
	user, err := c.ResolvePeer(userID)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf("user unavailable")
	}
	if restrict {
		_, err = c.EditBanned(chatID, user, &tg.BannedOptions{Mute: true, TillDate: int32(time.Now().Add(15 * time.Minute).Unix())})
	} else {
		_, err = c.EditBanned(chatID, user, &tg.BannedOptions{Unmute: true})
	}
	return err
}
func captchaKickUser(c *tg.Client, chatID int64, userID int64) error {
	user, err := c.ResolvePeer(userID)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf("user unavailable")
	}
	if _, err = c.EditBanned(chatID, user, &tg.BannedOptions{Ban: true}); err != nil {
		return err
	}
	_, err = c.EditBanned(chatID, user, &tg.BannedOptions{Unban: true})
	return err
}
func captchaCleanup(chatID, userID int64, c *tg.Client, msgID int32) {
	if msgID > 0 {
		_, _ = c.DeleteMessages(chatID, []int32{msgID})
	}
}
func captchaFailed(c *tg.Client, st *captchaState) bool {
	if !claimCaptcha(st) {
		return false
	}
	defer captchaStates.CompareAndDelete(captchaStateKey(st.ChatID, st.UserID), st)
	err := captchaKickUser(c, st.ChatID, st.UserID)
	captchaCleanup(st.ChatID, st.UserID, c, st.MessageID)
	if err != nil {
		log.Printf("captcha removal: %v", err)
		if st.Restricted {
			_ = captchaRestrictUser(c, st.ChatID, st.UserID, false)
		}
		return false
	}
	_, _ = c.SendMessage(st.ChatID, fmt.Sprintf("%s failed the captcha and was removed.", html.EscapeString(st.UserName)))
	return true
}
func captchaScheduleTimeout(c *tg.Client, st *captchaState) {
	go func() {
		timer := time.NewTimer(time.Until(st.Deadline))
		defer timer.Stop()
		select {
		case <-timer.C:
			captchaFailed(c, st)
		case <-st.Cancel:
		}
	}()
}
func captchaPassed(client *tg.Client, st *captchaState) bool {
	if !claimCaptcha(st) {
		return false
	}
	defer captchaStates.CompareAndDelete(captchaStateKey(st.ChatID, st.UserID), st)
	if st.Restricted {
		if err := captchaRestrictUser(client, st.ChatID, st.UserID, false); err != nil {
			log.Printf("captcha unmute: %v", err)
			_, _ = client.SendMessage(st.ChatID, "Verification succeeded, but I could not unmute the member. An admin needs to unmute them.")
		}
	}
	captchaCleanup(st.ChatID, st.UserID, client, st.MessageID)
	if st.User != nil {
		sendWelcome(client, st.ChatID, st.User)
	}
	return true
}

func startCaptcha(p *tg.ParticipantUpdate) {
	chatID := p.ChatID()
	lock := &captchaSetupLocks[uint64(chatID)%64]
	lock.Lock()
	defer lock.Unlock()
	cfg := getCaptchaConfig(chatID)
	if !cfg.Enabled {
		return
	}
	userID := p.User.ID
	key := captchaStateKey(chatID, userID)

	userName := p.User.FirstName
	if userName == "" {
		userName = "user"
	}
	mention := fmt.Sprintf("<a href=\"tg://user?id=%d\">%s</a>", userID, html.EscapeString(userName))
	deadline := time.Now().Add(time.Duration(cfg.Timeout) * time.Second)

	st := &captchaState{
		Ready:    make(chan struct{}),
		UserID:   userID,
		ChatID:   chatID,
		Type:     cfg.Type,
		Deadline: deadline,
		Cancel:   make(chan struct{}),
		UserName: userName,
		User:     p.User,
	}
	if _, exists := captchaStates.LoadOrStore(key, st); exists {
		return
	}
	defer close(st.Ready)
	// Text challenges need members to be able to send their answer. The watcher
	// consumes their other messages until they reply to the challenge.
	restricted := cfg.Type != captchaTypeText
	st.Restricted = restricted
	if restricted {
		if err := captchaRestrictUser(p.Client, chatID, userID, true); err != nil {
			captchaStates.CompareAndDelete(key, st)
			log.Printf("captcha restrict: %v", err)
			return
		}
	}
	defer func() {
		if st.MessageID == 0 {
			captchaStates.CompareAndDelete(key, st)
			if restricted {
				_ = captchaRestrictUser(p.Client, chatID, userID, false)
			}
		}
	}()

	switch cfg.Type {
	case captchaTypeBtn:
		st.Answer = "ok"
		b := tg.Button
		kb := tg.NewKeyboard().AddRow(
			b.Data("I'm not a bot", fmt.Sprintf("%sbtn:%d:%d", captchaPrefix, chatID, userID)),
		).Build()
		msg, err := p.Client.SendMessage(chatID, fmt.Sprintf(
			"Welcome %s! Please click the button below within %d seconds to verify you are human.",
			mention, cfg.Timeout,
		), &tg.SendOptions{ReplyMarkup: kb})
		if err == nil && msg != nil {
			st.MessageID = msg.ID
		}

	case captchaTypeMath:
		question, answer := captchaGenMath()
		st.Answer = answer
		img, err := captchaRenderText(question, 360, 140, 36)
		if err != nil {
			return
		}
		defer os.Remove(img)

		correct, _ := strconv.Atoi(answer)
		opts := []int{correct}
		for len(opts) < 4 {
			delta := rand.Intn(11) - 5
			if delta == 0 {
				delta = 1
			}
			candidate := correct + delta
			if candidate < 0 {
				candidate = correct + rand.Intn(5) + 1
			}
			dup := false
			for _, o := range opts {
				if o == candidate {
					dup = true
					break
				}
			}
			if !dup {
				opts = append(opts, candidate)
			}
		}
		rand.Shuffle(len(opts), func(i, j int) { opts[i], opts[j] = opts[j], opts[i] })

		b := tg.Button
		kb := tg.NewKeyboard()
		row := []tg.KeyboardInlineButton{}
		for i, o := range opts {
			label := strconv.Itoa(o)
			data := fmt.Sprintf("%smath:%d:%d:%s", captchaPrefix, chatID, userID, label)
			row = append(row, b.Data(label, data))
			if (i+1)%2 == 0 {
				kb.AddRow(row...)
				row = []tg.KeyboardInlineButton{}
			}
		}
		if len(row) > 0 {
			kb.AddRow(row...)
		}

		msg, err := modules.TransferSendMedia(p.Client, chatID, img, &tg.MediaOptions{
			Caption: fmt.Sprintf(
				"Welcome %s! Solve the captcha within %d seconds. Pick the correct answer below.",
				mention, cfg.Timeout,
			),
			FileName:    "captcha.png",
			MimeType:    "image/png",
			ReplyMarkup: kb.Build(),
		})
		if err == nil && msg != nil {
			st.MessageID = msg.ID
		}

	case captchaTypeText:
		text := captchaRandomString(5)
		st.Answer = text
		img, err := captchaRenderText(text, 320, 120, 44)
		if err != nil {
			return
		}
		defer os.Remove(img)

		msg, err := modules.TransferSendMedia(p.Client, chatID, img, &tg.MediaOptions{
			Caption: fmt.Sprintf(
				"Welcome %s! Reply to this message with the 5 characters shown within %d seconds (case-insensitive).",
				mention, cfg.Timeout,
			),
			FileName: "captcha.png",
			MimeType: "image/png",
		})
		if err == nil && msg != nil {
			st.MessageID = msg.ID
		}
	}

	if st.MessageID == 0 {
		return
	}
	st.Deadline = time.Now().Add(time.Duration(cfg.Timeout) * time.Second)
	captchaScheduleTimeout(p.Client, st)
}

func CaptchaCallbackHandler(c *tg.CallbackQuery) error {
	parts := strings.Split(strings.TrimPrefix(c.DataString(), captchaPrefix), ":")
	if len(parts) < 3 {
		return nil
	}
	chatID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil
	}
	userID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil
	}
	if c.SenderID != userID {
		c.Answer("This captcha is not for you.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	raw, ok := captchaStates.Load(captchaStateKey(chatID, userID))
	if !ok {
		c.Answer("Captcha expired.")
		return nil
	}
	st := raw.(*captchaState)
	<-st.Ready
	// Bind callbacks to the actual message as well as the member and chat.
	if st.MessageID == 0 || c.GetChatID() != st.ChatID || c.MessageID != st.MessageID || st.Finished.Load() || time.Now().After(st.Deadline) {
		c.Answer("Captcha expired.")
		return nil
	}
	correct := false
	switch {
	case parts[0] == "btn" && st.Type == captchaTypeBtn:
		correct = true
	case parts[0] == "math" && st.Type == captchaTypeMath && len(parts) == 4:
		correct = parts[3] == st.Answer
	default:
		return nil
	}
	if correct {
		if captchaPassed(c.Client, st) {
			c.Answer("Verified!")
		} else {
			c.Answer("Already handled.")
		}
	} else {
		if captchaFailed(c.Client, st) {
			c.Answer("Wrong answer. Removed.", &tg.CallbackOptions{Alert: true})
		} else {
			c.Answer("Challenge ended.")
		}
	}
	return nil
}
func CaptchaMessageWatcher(m *tg.NewMessage) error {
	if m.IsPrivate() || m.SenderID() == 0 {
		return nil
	}
	raw, ok := captchaStates.Load(captchaStateKey(m.ChatID(), m.SenderID()))
	if !ok {
		return nil
	}
	st := raw.(*captchaState)
	<-st.Ready
	if st.MessageID == 0 || st.Finished.Load() {
		return nil
	}
	if st.Type != captchaTypeText {
		return tg.ErrEndGroup
	}
	// An unrelated message must not count as a wrong answer.
	if m.ReplyToMsgID() != st.MessageID {
		_, _ = m.Client.DeleteMessages(m.ChatID(), []int32{m.ID})
		return tg.ErrEndGroup
	}
	if time.Now().After(st.Deadline) {
		captchaFailed(m.Client, st)
		return tg.ErrEndGroup
	}
	text := strings.ToUpper(strings.TrimSpace(m.Text()))
	if text == "" {
		return tg.ErrEndGroup
	}
	if text == strings.ToUpper(st.Answer) {
		captchaPassed(m.Client, st)
	} else {
		captchaFailed(m.Client, st)
	}
	_, _ = m.Client.DeleteMessages(m.ChatID(), []int32{m.ID})
	return tg.ErrEndGroup
}

func CaptchaCommandHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("Captcha is only available in groups")
		return nil
	}
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "change_info") {
		m.Reply("You need Change Info permission to manage captcha")
		return nil
	}

	args := strings.Fields(m.Args())
	cfg := getCaptchaConfig(m.ChatID())

	if len(args) == 0 {
		status := "off"
		if cfg.Enabled {
			status = "on"
		}
		m.Reply(fmt.Sprintf(`<b>Captcha Settings</b>

Status: <b>%s</b>
Type: <b>%s</b>
Timeout: <b>%d seconds</b>

<b>Usage:</b>
/captcha on|off|status
/captcha type &lt;button|math|text&gt;
/captcha timeout &lt;seconds&gt;`, status, html.EscapeString(cfg.Type), cfg.Timeout))
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "on", "enable", "yes", "1":
		cfg.Enabled = true
		if err := saveCaptchaConfig(m.ChatID(), cfg); err != nil {
			m.Reply("Failed to enable captcha")
			return nil
		}
		m.Reply(fmt.Sprintf("Captcha <b>enabled</b>\nType: <b>%s</b>\nTimeout: <b>%d s</b>", html.EscapeString(cfg.Type), cfg.Timeout))
	case "off", "disable", "no", "0":
		lock := &captchaSetupLocks[uint64(m.ChatID())%64]
		lock.Lock()
		defer lock.Unlock()
		cfg.Enabled = false
		if err := saveCaptchaConfig(m.ChatID(), cfg); err != nil {
			m.Reply("Failed to disable captcha")
			return nil
		}
		captchaStates.Range(func(key, value any) bool {
			st := value.(*captchaState)
			if st.ChatID == m.ChatID() {
				<-st.Ready
				if claimCaptcha(st) {
					if st.Restricted {
						_ = captchaRestrictUser(m.Client, st.ChatID, st.UserID, false)
					}
					captchaCleanup(st.ChatID, st.UserID, m.Client, st.MessageID)
					captchaStates.CompareAndDelete(key, st)
				}
			}
			return true
		})
		m.Reply("Captcha <b>disabled</b>")
	case "status":
		status := "off"
		if cfg.Enabled {
			status = "on"
		}
		m.Reply(fmt.Sprintf(`<b>Captcha Status</b>

State: <b>%s</b>
Type: <b>%s</b>
Timeout: <b>%d seconds</b>`, status, html.EscapeString(cfg.Type), cfg.Timeout))
	case "type":
		if len(args) < 2 {
			m.Reply("Usage: /captcha type &lt;button|math|text&gt;")
			return nil
		}
		t := strings.ToLower(args[1])
		if t == "image" || t == "img" {
			t = captchaTypeText
		}
		if t != captchaTypeBtn && t != captchaTypeMath && t != captchaTypeText {
			m.Reply("Invalid type. Options: button, math, text")
			return nil
		}
		cfg.Type = t
		if err := saveCaptchaConfig(m.ChatID(), cfg); err != nil {
			m.Reply("Failed to update captcha type")
			return nil
		}
		m.Reply(fmt.Sprintf("Captcha type set to <b>%s</b>", html.EscapeString(t)))
	case "timeout":
		if len(args) < 2 {
			m.Reply("Usage: /captcha timeout &lt;seconds&gt;")
			return nil
		}
		secs, err := strconv.Atoi(args[1])
		if err != nil || secs < 15 || secs > 600 {
			m.Reply("Invalid timeout. Must be between 15 and 600 seconds")
			return nil
		}
		cfg.Timeout = secs
		if err := saveCaptchaConfig(m.ChatID(), cfg); err != nil {
			m.Reply("Failed to update captcha timeout")
			return nil
		}
		m.Reply(fmt.Sprintf("Captcha timeout set to <b>%d seconds</b>", secs))
	default:
		m.Reply("Usage: /captcha on|off|status | type &lt;button|math|text&gt; | timeout &lt;seconds&gt;")
	}
	return nil
}

func registerWelcomeHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:setwelcome", SetWelcomeHandler)
	modules.OnCommand(c, "cmd:setgoodbye", SetGoodbyeHandler)
	modules.OnCommand(c, "cmd:goodbye", GoodbyeToggleHandler)
	modules.OnCommand(c, "cmd:clearwelcome", ClearWelcomeHandler)
	modules.OnCommand(c, "cmd:cleargoodbye", ClearGoodbyeHandler)
	modules.OnCommand(c, "cmd:cleanwelcome", CleanServiceHandler)
	modules.OnCommand(c, "cmd:wautodelete", WelcomeAutoDeleteHandler)
	modules.OnCommand(c, "cmd:gautodelete", GoodbyeAutoDeleteHandler)
	modules.OnCommand(c, "cmd:cleangoodbye", CleanGoodbyeHandler)
	modules.OnCommand(c, "cmd:testwelcome", func(m *tg.NewMessage) error { return previewGreeting(m, false) })
	modules.OnCommand(c, "cmd:testgoodbye", func(m *tg.NewMessage) error { return previewGreeting(m, true) })
	modules.OnCommand(c, "cmd:welcomesettings", WelcomeSettingsHandler)
	modules.OnCommand(c, "cmd:greetings", WelcomeSettingsHandler)
	modules.OnCommand(c, "cmd:greet", WelcomeToggleHandler)
	modules.OnCommand(c, "cmd:welcome", WelcomeToggleHandler)
	modules.OnCommand(c, "cmd:captcha", CaptchaCommandHandler)
	c.On("callback:"+captchaPrefix, CaptchaCallbackHandler)
	modules.OnCommand(c, "cmd:joinfilter", JoinFilterCommandHandler)
	c.On(tg.OnParticipant, WelcomeHandler)
	// ConversationGroup runs synchronously before ordinary handlers. Other
	// groups run alongside default handlers and cannot gate pending members.
	c.On(tg.OnNewMessage, CaptchaMessageWatcher).SetGroup(tg.ConversationGroup)
}

func init() {
	modules.QueueHandlerRegistration(registerWelcomeHandlers)

	modules.Mods.AddModule("Welcome", `<b>Greetings + Captcha Module</b>

Welcomes new users, greets returners, and gates joins behind a captcha challenge when enabled.

<b>Welcome Commands:</b>
 - /setwelcome &lt;text&gt; - Set welcome message
 - /welcome on/off - Toggle welcome messages
 - /clearwelcome - Clear welcome message
 - /cleanwelcome on/off - Delete previous welcome
 - /wautodelete &lt;time&gt; - Auto-delete welcome

<b>Goodbye Commands:</b>
 - /setgoodbye &lt;text&gt; - Set goodbye message
 - /goodbye on/off - Toggle goodbye messages
 - /cleargoodbye - Clear goodbye message
 - /cleangoodbye on/off - Delete previous goodbye
 - /gautodelete &lt;time&gt; - Auto-delete goodbye
 - /testwelcome and /testgoodbye - Preview without cleanup

<b>Captcha Commands:</b>
 - /captcha on|off|status - Toggle or view captcha
 - /captcha type &lt;button|math|text&gt; - Challenge style
 - /captcha timeout &lt;seconds&gt; - Verification window (15-600)

<b>Captcha types:</b>
 button - Click a single inline button
 math   - Solve arithmetic via 4 inline buttons (grainy image question)
 text   - Reply with the 5 characters shown in a noisy image

When captcha is on, the welcome message fires only AFTER the new member
verifies. Failures and timeouts get removed automatically.

<b>Variables:</b>
 {first}, {last}, {fullname}, {username}
 {mention}, {id}, {chatname}

<b>Button Format:</b>
 [Button](https://url)
 [same:Button](https://url) - Same row
 [Rules](rules) - Show rules`)
}
