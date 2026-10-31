package modules

import (
	"fmt"
	"html"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
)

var startTime = time.Now()

var StartPayloads = map[string]func(*tg.NewMessage) error{}

func StartHandle(m *tg.NewMessage) error {
	if fn, ok := StartPayloads[strings.TrimSpace(m.Args())]; ok {
		return fn(m)
	}
	greeting := "✨ <b>Hello there!</b> ✨\n\n"
	greeting += "I'm <b>Julia</b>, your friendly bot companion! 🤖💙\n\n"

	m.Reply(greeting)
	m.React("❤")
	return nil
}

func GatherSystemInfo(m *tg.NewMessage) error {
	msg, err := m.Reply("<code>...System Information...</code>")
	if err != nil || msg == nil {
		return err
	}

	system, err := gatherSystemInfo()
	if err != nil {
		msg.Edit("Failed to gather system info: <code>" + html.EscapeString(err.Error()) + "</code>")
		return nil
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	hostInfo, _ := host.Info()
	loadAvg, _ := load.Avg()

	info := "<b>System Information</b>\n\n"

	info += fmt.Sprintf("⚡ <b>Goroutines:</b> <code>%d</code> | <b>Process Memory:</b> <code>%s</code>\n\n", runtime.NumGoroutine(), system.ProcessMemory)

	info += "➜ <b><i>Performance</i></b>\n"
	info += fmt.Sprintf("   ├ <b>CPU Usage:</b> <code>%.2f%%</code>\n", system.CPUPerc)
	if loadAvg != nil {
		info += fmt.Sprintf("   ├ <b>Load Average:</b> <code>%.2f, %.2f, %.2f</code>\n", loadAvg.Load1, loadAvg.Load5, loadAvg.Load15)
	}
	info += fmt.Sprintf("   ├ <b>Heap Allocated:</b> <code>%s</code>\n", HumanBytes(memStats.Alloc))
	info += fmt.Sprintf("   ├ <b>Heap System:</b> <code>%s</code>\n", HumanBytes(memStats.Sys))
	info += fmt.Sprintf("   └ <b>Uptime:</b> <i>%s</i>\n\n", system.Uptime)

	info += "➜ <b><i>Hardware</i></b>\n"
	info += fmt.Sprintf("   ├ <b>CPU:</b> <i>%s</i>\n", system.CPUName)
	info += fmt.Sprintf("   ├ <b>Cores:</b> <code>%d</code>\n", runtime.NumCPU())
	info += fmt.Sprintf("   ├ <b>Memory:</b> <code>%s</code> / <code>%s</code> <i>(%.1f%%)</i>\n", system.MemUsed, system.MemTotal, system.MemPerc)
	info += fmt.Sprintf("   └ <b>Disk:</b> <code>%s</code> / <code>%s</code> <i>(%.1f%%)</i>\n\n", system.DiskUsed, system.DiskTotal, system.DiskPerc)

	info += "➜ <b><i>Runtime</i></b>\n"
	info += fmt.Sprintf("   ├ <b>Go Version:</b> <code>%s</code>\n", runtime.Version())
	info += fmt.Sprintf("   ├ <b>Platform:</b> <code>%s/%s</code>\n", runtime.GOOS, runtime.GOARCH)
	if hostInfo != nil {
		info += fmt.Sprintf("   ├ <b>Hostname:</b> <code>%s</code>\n", hostInfo.Hostname)
		info += fmt.Sprintf("   ├ <b>Boot Time:</b> <i>%s</i>\n", time.Unix(int64(hostInfo.BootTime), 0).Format("2006-01-02 15:04:05"))
	}
	info += fmt.Sprintf("   ├ <b>GC Cycles:</b> <code>%d</code> | <b>Pauses:</b> <code>%s</code>\n", memStats.NumGC, time.Duration(memStats.PauseTotalNs).Round(time.Millisecond))
	info += fmt.Sprintf("   └ <b>PID:</b> <code>%d</code>\n\n", system.ProcessID)
	info += "<i>Have a great day! 🌟</i>"
	msg.Edit(info)
	return nil
}

var dcLocationMap = map[int]string{
	1: "Miami, US",
	2: "Amsterdam, NL",
	3: "Miami, US",
	4: "Amsterdam, NL",
	5: "Singapore, SG",
}

func chatPhotoDcID(photo tg.ChatPhoto) int {
	if photo == nil {
		return 0
	}
	switch p := photo.(type) {
	case *tg.ChatPhotoObj:
		return int(p.DcID)
	default:
		return 0
	}
}

func formatDCInfo(dcId int) string {
	dcLoc := dcLocationMap[dcId]
	if dcLoc == "" {
		dcLoc = "Unknown"
	}
	dcFlag := getCountryFlag(dcId)
	if dcFlag == "" {
		dcFlag = "-"
	}
	return fmt.Sprintf("<code>DC%d</code>\n<b>Location:</b> %s\n<b>Flag:</b> %s", dcId, dcLoc, dcFlag)
}

func replyChannelInfo(m *tg.NewMessage, title string, channelPeerID string, username string, photo tg.ChatPhoto) {
	msg := "<b>Channel Info</b>\n\n"
	msg += fmt.Sprintf("<b>Title:</b> %s\n", html.EscapeString(title))
	if username != "" {
		msg += fmt.Sprintf("<b>Username:</b> @%s\n", strings.TrimPrefix(username, "@"))
	}
	msg += fmt.Sprintf("<b>ID:</b> <code>%s</code>\n", channelPeerID)
	msg += "<b>DC:</b> {{dcInfo}}\n"
	msg = strings.ReplaceAll(msg, "{{dcInfo}}", formatDCInfo(chatPhotoDcID(photo)))
	m.Reply(msg)
}

func replyGroupInfo(m *tg.NewMessage, title string, chatID int64, photo tg.ChatPhoto) {
	msg := "<b>Group Info</b>\n\n"
	msg += fmt.Sprintf("<b>Title:</b> %s\n", html.EscapeString(title))
	msg += fmt.Sprintf("<b>ID:</b> <code>-%d</code>\n", chatID)
	msg += "<b>DC:</b> {{dcInfo}}\n"
	msg = strings.ReplaceAll(msg, "{{dcInfo}}", formatDCInfo(chatPhotoDcID(photo)))
	m.Reply(msg)
}

func UserHandle(m *tg.NewMessage) error {
	var userID int64 = 0
	var userHash int64 = 0
	if m.IsReply() {
		r, err := m.GetReplyMessage()
		if err != nil || r == nil {
			m.Reply("Error: couldn't fetch the replied message")
			return nil
		}
		if r.SenderChat != nil && r.SenderChat.ID != 0 {
			replyChannelInfo(m, r.SenderChat.Title, fmt.Sprintf("-100%d", r.SenderChat.ID), "", r.SenderChat.Photo)
			return nil
		}

		userID = r.SenderID()
		if r.Sender == nil {
			m.Reply("Error: User not found")
			return nil
		}
		userHash = r.Sender.AccessHash
	} else if strings.TrimSpace(m.Args()) != "" {
		arg := strings.TrimSpace(m.Args())

		// Handle peer IDs like -1001234567890 (channels).
		if strings.HasPrefix(arg, "-100") {
			rest := strings.TrimPrefix(arg, "-100")
			if cid, err := strconv.ParseInt(rest, 10, 64); err == nil && cid > 0 {
				ch, err := m.Client.GetChannel(cid)
				if err != nil {
					m.Reply("Error: unable to fetch channel by -100 ID (need access hash). Try @username or reply/forward from that channel.")
					return nil
				}
				replyChannelInfo(m, ch.Title, arg, ch.Username, ch.Photo)
				return nil
			}
		}

		// Try username (user/group/channel).
		if ent, err := m.Client.ResolveUsername(arg); err == nil {
			switch v := ent.(type) {
			case *tg.UserObj:
				userID = v.ID
				userHash = v.AccessHash
			case *tg.ChatObj:
				replyGroupInfo(m, v.Title, v.ID, v.Photo)
				return nil
			case *tg.Channel:
				replyChannelInfo(m, v.Title, fmt.Sprintf("-100%d", v.ID), v.Username, v.Photo)
				return nil
			default:
				m.Reply("Error: unsupported username target")
				return nil
			}
		} else {
			// Not a username: try numeric user ID.
			if i, err := strconv.ParseInt(arg, 10, 64); err == nil {
				userID = i
				user, err := m.Client.GetUser(i)
				if err != nil {
					m.Reply("Error: " + err.Error())
					return nil
				}
				userHash = user.AccessHash
			} else {
				m.Reply("Error: invalid user/channel argument")
				return nil
			}
		}
	} else {
		userID = m.SenderID()
		if m.Sender == nil {
			m.Reply("Error: User not found")
			return nil
		}
		userHash = m.Sender.AccessHash
	}
	status := NewStatus(m, "Fetching user info…")
	user, err := m.Client.UsersGetFullUser(&tg.InputUserObj{
		UserID:     userID,
		AccessHash: userHash,
	})

	if err != nil {
		status.Edit("Error: " + err.Error())
		return nil
	}

	if user == nil || user.FullUser == nil || len(user.Users) == 0 {
		status.Edit("Error: user not found")
		return nil
	}
	uf := user.FullUser
	un, ok := user.Users[0].(*tg.UserObj)
	if !ok {
		status.Edit("Error: user not found")
		return nil
	}

	name := strings.TrimSpace(strings.TrimSpace(un.FirstName + " " + un.LastName))
	if name == "" {
		name = "(no name)"
	}

	userString := "<b>User Info</b>\n\n"
	userString += fmt.Sprintf("<b>Name:</b> %s\n", html.EscapeString(name))
	if un.Username != "" {
		userString += fmt.Sprintf("<b>Username:</b> @%s\n", un.Username)
	}
	userString += fmt.Sprintf("<b>ID:</b> <code>%d</code>\n", un.ID)
	userString += "<b>DC:</b> {{dcInfo}}\n"
	if un.Phone != "" {
		userString += fmt.Sprintf("<b>Phone:</b> +%s\n", un.Phone)
	}

	flags := []string{}
	if un.Verified {
		flags = append(flags, "verified")
	}
	if un.Premium {
		flags = append(flags, "premium")
	}
	if un.Bot {
		flags = append(flags, "bot")
	}
	if un.Support {
		flags = append(flags, "support")
	}
	if un.Restricted {
		flags = append(flags, "restricted")
	}
	if un.Scam {
		flags = append(flags, "scam")
	}
	if un.Fake {
		flags = append(flags, "fake")
	}
	if len(flags) > 0 {
		userString += fmt.Sprintf("<b>Flags:</b> %s\n", strings.Join(flags, ", "))
	}

	if un.Bot {
		botCaps := []string{}
		if un.BotChatHistory {
			botCaps = append(botCaps, "can read history")
		}
		if un.BotInlineGeo {
			botCaps = append(botCaps, "inline geo")
		}
		if un.BotAttachMenu {
			botCaps = append(botCaps, "attach menu")
		}
		if un.BotInlinePlaceholder != "" {
			botCaps = append(botCaps, "inline placeholder: "+html.EscapeString(un.BotInlinePlaceholder))
		}
		if len(botCaps) > 0 {
			userString += fmt.Sprintf("<b>Bot:</b> %s\n", strings.Join(botCaps, "; "))
		}
	}

	if uf.CommonChatsCount > 0 {
		userString += fmt.Sprintf("<b>Common groups:</b> %d\n", uf.CommonChatsCount)
	}

	if len(un.Usernames) > 0 {
		alts := []string{}
		for _, v := range un.Usernames {
			alts = append(alts, "@"+v.Username)
		}
		userString += "\n<b>Also known as:</b>\n"
		userString += strings.Join(alts, ", ") + "\n"
	}

	if uf.Birthday != nil {
		userString += "\n<b>Birthday:</b> " + parseBirthday(uf.Birthday.Day, uf.Birthday.Month, uf.Birthday.Year) + "\n"
	}

	estimator := NewUserDateEstimator()
	estimatedTS := estimator.Estimate(un.ID)
	formattedDate, age := estimator.FormatTime(estimatedTS)
	userString += "\n<b>Account:</b> " + age + "\n"
	userString += "<b>Created:</b> <code>" + formattedDate + "</code>\n"

	if uf.About != "" {
		userString += "\n<b>Bio:</b>\n<i>" + html.EscapeString(uf.About) + "</i>\n"
	}

	userString += "\n<a href=\"tg://user?id=" + strconv.FormatInt(un.ID, 10) + "\">View full profile</a>"

	var keyb = tg.NewKeyboard()
	profileButton := tg.Button.URL("View Profile", "tg://user?id="+strconv.FormatInt(un.ID, 10))
	profileButton.Style = &tg.KeyboardButtonStyle{BgPrimary: true}
	sendableUser, err := m.Client.GetSendableUser(un)
	if err == nil {
		profileButton.Type = &tg.InputInlineButtonTypeUserProfile{UserID: sendableUser}
	}
	keyb.AddRow(profileButton)

	var dcId = 0

	if uf.ProfilePhoto == nil {
		if uf.PersonalPhoto != nil {
			uf.ProfilePhoto = uf.PersonalPhoto
		} else if uf.FallbackPhoto != nil {
			uf.ProfilePhoto = uf.FallbackPhoto
		}
	}

	var buisnessSent bool = false

	if stick, ok := businessSticker(uf); ok {
		dcId = int(stick.DcID)
		sty := &tg.InputMediaDocument{
			ID: &tg.InputDocumentObj{
				ID:            stick.ID,
				AccessHash:    stick.AccessHash,
				FileReference: stick.FileReference,
			},
		}
		status.Done()
		if _, err := TransferReplyMedia(m, sty, &tg.MediaOptions{
			ReplyMarkup: keyb.Build(),
		}); err == nil {
			buisnessSent = true
		}
	}

	mediaOpt := &tg.MediaOptions{
		Caption: userString,
	}

	sendOpt := &tg.SendOptions{}

	if !buisnessSent {
		mediaOpt.ReplyMarkup = keyb.Build()
		sendOpt.ReplyMarkup = keyb.Build()
	}

	p, _ := uf.ProfilePhoto.(*tg.PhotoObj)
	if pp, ok := uf.PersonalPhoto.(*tg.PhotoObj); ok {
		p = pp
	}
	if p != nil {
		dcId = int(p.DcID)
		var inp tg.InputMedia
		inp = &tg.InputMediaPhoto{
			ID: &tg.InputPhotoObj{
				ID:            p.ID,
				AccessHash:    p.AccessHash,
				FileReference: p.FileReference,
			},
			Spoiler: true,
		}
		if len(p.VideoSizes) > 0 {
			dled, err := TransferDownloadMedia(m.Client, p, &tg.DownloadOptions{
				IsVideo: true,
			})
			if err == nil {
				defer os.Remove(dled)
				ul, err := TransferSendableMedia(m.Client, dled, &tg.MediaMetadata{NoSoundVideo: true, Spoiler: true, MimeType: "video/mp4"})
				if err == nil {
					inp = ul
				}
			}
		}

		userString = strings.ReplaceAll(userString, "{{dcInfo}}", formatDCInfo(dcId))
		mediaOpt.Caption = userString
		status.Done()
		if _, err := TransferReplyMedia(m, inp, mediaOpt); err != nil {
			status.Edit(userString, sendOpt)
		}
	} else {
		userString = strings.ReplaceAll(userString, "{{dcInfo}}", formatDCInfo(dcId))
		status.Edit(userString, sendOpt)
	}
	return nil
}

func businessSticker(uf *tg.UserFull) (*tg.DocumentObj, bool) {
	if uf.BusinessIntro == nil {
		return nil, false
	}
	d, ok := uf.BusinessIntro.Sticker.(*tg.DocumentObj)
	return d, ok
}

func getCountryFlag(dcId int) string {
	flags := map[int]string{
		1: "🇺🇸",
		2: "🇳🇱",
		3: "🇺🇸",
		4: "🇳🇱",
		5: "🇸🇬",
	}
	if flag, ok := flags[dcId]; ok {
		return flag
	}
	return ""
}

var st = time.Now()

func PingHandle(m *tg.NewMessage) error {
	startTime := time.Now()
	sentMessage, err := m.Reply("Pinging...")
	if err != nil || sentMessage == nil {
		return err
	}
	_, err = sentMessage.Edit(fmt.Sprintf("<code>Pong!</code> <code>%s</code>\n<code>Uptime ⚡ </code><b>%s</b>", time.Since(startTime).String(), time.Since(st).String()))
	return err
}

var istZone = time.FixedZone("IST", 5*3600+1800)

func NewYearHandle(m *tg.NewMessage) error {
	now := time.Now().In(istZone)
	target := now.Year() + 1
	remaining := time.Date(target, time.January, 1, 0, 0, 0, 0, istZone).Sub(now)

	days := int(remaining.Hours()) / 24
	hours := int(remaining.Hours()) % 24
	minutes := int(remaining.Minutes()) % 60
	seconds := int(remaining.Seconds()) % 60
	milliseconds := remaining.Milliseconds() % 1000

	m.Reply(fmt.Sprintf("<b>New Year %d Countdown</b> <i>(IST)</i>\n<code>%d days, %02d:%02d:%02d.%03d</code>", target, days, hours, minutes, seconds, milliseconds))
	return nil
}

func init() {
	Mods.AddModule("Start", `<b>Start</b>

 - <code>/start</code> - check if the bot is alive
 - <code>/ping</code> - response time and uptime
 - <code>/sys</code> (alias <code>/systeminfo</code>) - host, memory, CPU and runtime stats
 - <code>/info [user | @username | ID | -100channelID]</code> - user, group or channel info; reply to a message to inspect its sender. Ex: <code>/info @durov</code>
 - <code>/new</code> - countdown to the next New Year (IST)`)
}

func registerStartHandlers() {
	c := Client
	OnCommand(c, "cmd:start", StartHandle)
	OnCommand(c, "cmd:ping", PingHandle)
	OnCommand(c, "cmd:new", NewYearHandle)
	OnCommand(c, "cmd:sys", GatherSystemInfo)
	OnCommand(c, "cmd:systeminfo", GatherSystemInfo)
	OnCommand(c, "cmd:info", UserHandle)
}

func init() {
	QueueHandlerRegistration(registerStartHandlers)
}
