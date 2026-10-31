package extras

import (
	"errors"
	"fmt"
	"html"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	"main/modules"
	"main/modules/db"
)

func formatWelcomeText(text string, user *tg.UserObj, chat *tg.Channel) string {
	if user == nil {
		return text
	}
	name := user.FirstName
	if name == "" {
		name = "User"
	}
	mention := fmt.Sprintf(`<a href="tg://user?id=%d">%s</a>`, user.ID, html.EscapeString(name))
	username := mention
	if user.Username != "" {
		username = "@" + html.EscapeString(user.Username)
	}
	title := "this group"
	if chat != nil {
		title = html.EscapeString(chat.Title)
	}
	// One pass: placeholder-looking text inside a name stays literal.
	return strings.NewReplacer(
		"{first}", html.EscapeString(name), "{last}", html.EscapeString(user.LastName),
		"{fullname}", html.EscapeString(strings.TrimSpace(name+" "+user.LastName)),
		"{username}", username, "{mention}", mention, "{id}", strconv.FormatInt(user.ID, 10),
		"{chatname}", title, "{chattitle}", title,
	).Replace(text)
}

func greetingAdmin(m *tg.NewMessage) bool {
	if m.IsPrivate() {
		m.Reply("Greetings are available in groups.")
		return false
	}
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "change_info") {
		m.Reply("You need Change Info permission to change greetings.")
		return false
	}
	return true
}

func greetingMedia(m *tg.NewMessage) (string, string) {
	if m == nil || m.File == nil {
		return "", ""
	}
	kind := ""
	switch {
	case m.Photo() != nil:
		kind = "photo"
	case m.Sticker() != nil:
		kind = "sticker"
	case m.Animation() != nil:
		kind = "animation"
	case m.Video() != nil:
		kind = "video"
	case m.Document() != nil:
		kind = "document"
	}
	if kind == "" {
		return "", ""
	}
	return kind, m.File.FileID
}

func setGreeting(m *tg.NewMessage, goodbye bool) error {
	if !greetingAdmin(m) {
		return nil
	}
	content, kind, fileID := m.Args(), "", ""
	if m.IsReply() {
		reply, err := m.GetReplyMessage()
		if err != nil || reply == nil {
			m.Reply("Could not read the replied message.")
			return nil
		}
		kind, fileID = greetingMedia(reply)
		if content == "" {
			content = reply.RawText()
		}
	}
	if content == "" && fileID == "" {
		m.Reply("Add text after the command or reply to text/media.\nVariables: {first}, {last}, {fullname}, {username}, {mention}, {id}, {chatname}\nButtons: [Website](https://example.com), [same:Rules](rules)")
		return nil
	}
	content, buttons := parseButtons(content)
	err := db.ModifyGreeting(m.ChatID(), goodbye, func(cfg *db.WelcomeMessage) {
		cfg.Content, cfg.MediaType, cfg.FileID = content, kind, fileID
		cfg.Buttons, cfg.Enabled = serializeButtons(buttons), true
	})
	if err != nil {
		m.Reply("Could not save the greeting. Please try again.")
		return err
	}
	label := "welcome"
	if goodbye {
		label = "goodbye"
	}
	_, err = m.Reply("Saved and enabled. Preview with /test" + label + ".")
	return err
}

func SetWelcomeHandler(m *tg.NewMessage) error { return setGreeting(m, false) }
func SetGoodbyeHandler(m *tg.NewMessage) error { return setGreeting(m, true) }

func greetingSetting(m *tg.NewMessage, goodbye bool, setting string) error {
	if !greetingAdmin(m) {
		return nil
	}
	arg := strings.ToLower(strings.TrimSpace(m.Args()))
	var enabled bool
	seconds := 0
	switch setting {
	case "clear":
	case "autodelete":
		var err error
		seconds, err = greetingDuration(arg)
		if err != nil {
			m.Reply(err.Error())
			return nil
		}
	default:
		switch arg {
		case "on", "yes", "enable", "1":
			enabled = true
		case "off", "no", "disable", "0":
		default:
			return WelcomeSettingsHandler(m)
		}
	}
	err := db.ModifyGreeting(m.ChatID(), goodbye, func(cfg *db.WelcomeMessage) {
		switch setting {
		case "clear":
			*cfg = db.WelcomeMessage{}
		case "autodelete":
			cfg.AutoDeleteSec = seconds
		case "clean":
			cfg.DeletePrevious = enabled
		default:
			cfg.Enabled = enabled
		}
	})
	if err != nil {
		m.Reply("Could not save greeting settings. Please try again.")
		return err
	}
	return WelcomeSettingsHandler(m)
}

func greetingDuration(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "off" || s == "0" {
		return 0, nil
	}
	multiplier := int64(1)
	if len(s) > 0 {
		switch s[len(s)-1] {
		case 's':
			s = s[:len(s)-1]
		case 'm':
			multiplier = 60
			s = s[:len(s)-1]
		case 'h':
			multiplier = 3600
			s = s[:len(s)-1]
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 || n > 86400/multiplier || n*multiplier < 5 {
		return 0, errors.New("Use 5s to 24h (for example 30s or 5m), or off.")
	}
	return int(n * multiplier), nil
}

func WelcomeToggleHandler(m *tg.NewMessage) error     { return greetingSetting(m, false, "enabled") }
func GoodbyeToggleHandler(m *tg.NewMessage) error     { return greetingSetting(m, true, "enabled") }
func ClearWelcomeHandler(m *tg.NewMessage) error      { return greetingSetting(m, false, "clear") }
func ClearGoodbyeHandler(m *tg.NewMessage) error      { return greetingSetting(m, true, "clear") }
func CleanServiceHandler(m *tg.NewMessage) error      { return greetingSetting(m, false, "clean") }
func CleanGoodbyeHandler(m *tg.NewMessage) error      { return greetingSetting(m, true, "clean") }
func WelcomeAutoDeleteHandler(m *tg.NewMessage) error { return greetingSetting(m, false, "autodelete") }
func GoodbyeAutoDeleteHandler(m *tg.NewMessage) error { return greetingSetting(m, true, "autodelete") }

func greetingStatus(cfg *db.WelcomeMessage) string {
	if cfg == nil {
		return "off (not configured)"
	}
	status := "off"
	if cfg.Enabled {
		status = "on"
	}
	text := "default text"
	if cfg.Content != "" || cfg.FileID != "" {
		text = "custom message"
	}
	clean := "off"
	if cfg.DeletePrevious {
		clean = "on"
	}
	timer := "off"
	if cfg.AutoDeleteSec > 0 {
		timer = fmt.Sprintf("%ds", cfg.AutoDeleteSec)
	}
	return fmt.Sprintf("%s · %s\nDelete previous: %s · Auto-delete: %s", status, text, clean, timer)
}

func WelcomeSettingsHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		_, err := m.Reply("Greetings are available in groups.")
		return err
	}
	w, err := db.GetWelcome(m.ChatID())
	if err != nil {
		return err
	}
	g, err := db.GetGoodbye(m.ChatID())
	if err != nil {
		return err
	}
	_, err = m.Reply(fmt.Sprintf(`<b>Greetings</b>

<b>Welcome:</b> %s
<b>Goodbye:</b> %s

/setwelcome · /setgoodbye — set text or reply to media
/welcome on|off · /goodbye on|off
/testwelcome · /testgoodbye — preview
/cleanwelcome on|off · /cleangoodbye on|off
/wautodelete 30s|off · /gautodelete 30s|off
/clearwelcome · /cleargoodbye`, greetingStatus(w), greetingStatus(g)))
	return err
}

func participantPresent(p tg.ChannelParticipant) bool {
	switch p := p.(type) {
	case nil, *tg.ChannelParticipantLeft:
		return false
	case *tg.ChannelParticipantBanned:
		return !p.Left
	default:
		return true
	}
}

func WelcomeHandler(p *tg.ParticipantUpdate) error {
	if p.User == nil || p.User.Bot {
		return nil
	}
	joined := !participantPresent(p.Old) && participantPresent(p.New)
	left := participantPresent(p.Old) && !participantPresent(p.New)
	if left {
		if raw, ok := captchaStates.Load(captchaStateKey(p.ChatID(), p.User.ID)); ok {
			st := raw.(*captchaState)
			<-st.Ready
			if claimCaptcha(st) {
				captchaCleanup(p.ChatID(), p.User.ID, p.Client, st.MessageID)
				captchaStates.CompareAndDelete(captchaStateKey(st.ChatID, st.UserID), st)
			}
			return nil
		}
		return sendGreeting(p.Client, p.ChatID(), p.User, true, false)
	}
	if !joined {
		return nil
	}
	if reason, matched := joinFilterMatch(p.ChatID(), p.User); matched {
		joinFilterBan(p.Client, p.ChatID(), p.User, reason)
		return nil
	}
	if getCaptchaConfig(p.ChatID()).Enabled {
		startCaptcha(p)
		return nil
	}
	sendWelcome(p.Client, p.ChatID(), p.User)
	return nil
}

// Striped locks bound memory use and keep consecutive joins/cleanup in order.
var greetingLocks [64]sync.Mutex

func sendWelcome(client *tg.Client, chatID int64, user *tg.UserObj) {
	if err := sendGreeting(client, chatID, user, false, false); err != nil {
		log.Printf("send welcome: %v", err)
	}
}

func greetingContent(cfg *db.WelcomeMessage, goodbye bool) string {
	if cfg.Content != "" {
		return cfg.Content
	}
	if goodbye {
		return "Goodbye {first}!"
	}
	return "Hey {mention}, welcome to {chatname}!"
}

func sendGreeting(client *tg.Client, chatID int64, user *tg.UserObj, goodbye, preview bool) error {
	if user == nil {
		return errors.New("greeting user unavailable")
	}
	lock := &greetingLocks[uint64(chatID)%uint64(len(greetingLocks))]
	lock.Lock()
	defer lock.Unlock()
	cfg, err := db.GetGreeting(chatID, goodbye)
	if err != nil {
		return err
	}
	if !preview && (cfg == nil || !cfg.Enabled) {
		return nil
	}
	if cfg == nil {
		cfg = &db.WelcomeMessage{}
	}
	channel, _ := client.GetChannel(chatID)
	text := formatWelcomeText(greetingContent(cfg, goodbye), user, channel)
	_, buttons := parseButtons(cfg.Buttons)
	keyboard := buildKeyboard(buttons)
	var sent *tg.NewMessage
	var ids []int32
	if cfg.FileID != "" {
		media, resolveErr := tg.ResolveBotFileID(cfg.FileID)
		if resolveErr == nil {
			if cfg.MediaType == "sticker" {
				// Telegram stickers cannot carry captions. Keep text and buttons
				// in a companion message and clean up both as one greeting.
				sticker, stickerErr := modules.TransferSendMedia(client, chatID, media, &tg.MediaOptions{})
				if stickerErr == nil && sticker != nil {
					ids = append(ids, sticker.ID)
				}
			} else {
				sent, err = modules.TransferSendMedia(client, chatID, media, &tg.MediaOptions{Caption: text, ReplyMarkup: keyboard, ParseMode: "HTML"})
			}
		}
	}
	if sent == nil { // Expired media must not silently swallow greetings.
		sent, err = client.SendMessage(chatID, text, &tg.SendOptions{ReplyMarkup: keyboard, ParseMode: "HTML"})
	}
	if err != nil {
		if len(ids) > 0 {
			_, _ = client.DeleteMessages(chatID, ids)
		}
		return err
	}
	if sent == nil {
		return errors.New("greeting was not sent")
	}
	if preview {
		return nil
	}
	ids = append(ids, sent.ID)
	if cfg.DeletePrevious {
		last, getErr := db.GetLastGreetingIDs(chatID, goodbye)
		if getErr != nil {
			return getErr
		}
		// Keep the old greeting if sending the replacement failed.
		if err := db.SetLastGreetingIDs(chatID, goodbye, ids); err != nil {
			return err
		}
		if len(last) > 0 {
			_, _ = client.DeleteMessages(chatID, last)
		}
	}
	if cfg.AutoDeleteSec >= 5 && cfg.AutoDeleteSec <= 86400 {
		time.AfterFunc(time.Duration(cfg.AutoDeleteSec)*time.Second, func() { _, _ = client.DeleteMessages(chatID, ids) })
	}
	return nil
}

func previewGreeting(m *tg.NewMessage, goodbye bool) error {
	if !greetingAdmin(m) {
		return nil
	}
	if err := sendGreeting(m.Client, m.ChatID(), m.Sender, goodbye, true); err != nil {
		m.Reply("Could not send the preview. Check the template HTML and bot permissions.")
		return err
	}
	return nil
}
