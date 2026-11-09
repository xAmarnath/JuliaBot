package extras

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"main/internal/imdb/scraper"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	modules "main/modules"
	"main/modules/db"

	"github.com/patrickmn/go-cache"
	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
)

func Gban(m *tg.NewMessage) error {
	user, reason, err := modules.GetUserFromContext(m)
	if err != nil {
		m.Reply("Error: " + err.Error())
		return nil
	}
	message, _ := m.Reply("Enforcing global ban...")
	done := 0
	m.Client.Broadcast(context.Background(), nil, func(c tg.Chat) error {
		_, err := m.Client.EditBanned(c, user, &tg.BannedOptions{Ban: true})
		if err == nil {
			done++
		}
		return nil
	}, 600)

	message.Edit(fmt.Sprintf("Global ban enforced in %d groups.\nReason: %s", done, reason))
	return nil
}

func Ungban(m *tg.NewMessage) error {
	user, _, err := modules.GetUserFromContext(m)
	if err != nil {
		m.Reply("Error: " + err.Error())
		return nil
	}
	message, _ := m.Reply("Removing global ban...")
	done := 0
	m.Client.Broadcast(context.Background(), nil, func(c tg.Chat) error {
		_, err := m.Client.EditBanned(c, user, &tg.BannedOptions{Ban: false})
		if err == nil {
			done++
		}
		return nil
	}, 600)
	message.Edit(fmt.Sprintf("Global ban removed in %d groups.", done))
	return nil
}

func NightModeHandler(m *tg.NewMessage) error {
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "change_info") {
		m.Reply("You need Change Info rights to use this command")
		return nil
	}

	args := m.Args()
	if args == "" {
		m.Reply("Usage: /nightmode on/off")
		return nil
	}

	var enable bool
	switch strings.ToLower(args) {
	case "on":
		enable = true
	case "off":
		enable = false
	default:
		m.Reply("Usage: /nightmode on/off")
		return nil
	}

	chat, err := m.Client.GetChat(m.ChatID())
	if err != nil {
		m.Reply("Error fetching chat info")
		return nil
	}

	current := chat.DefaultBannedRights
	if current == nil {
		current = &tg.ChatBannedRights{}
	}

	current.SendMessages = enable

	_, err = m.Client.MessagesEditChatDefaultBannedRights(m.Peer, current)
	if err != nil {
		m.Reply("Failed to toggle night mode: " + err.Error())
		return nil
	}

	if enable {
		m.Reply("Night mode enabled. Messages are restricted.")
	} else {
		m.Reply("Night mode disabled. Messages allowed.")
	}
	return nil
}

var popularLangCodes = []struct {
	Code string
	Name string
}{
	{"en", "English"}, {"es", "Spanish"}, {"fr", "French"}, {"de", "German"},
	{"it", "Italian"}, {"pt", "Portuguese"}, {"ru", "Russian"}, {"zh", "Chinese"},
	{"ja", "Japanese"}, {"ko", "Korean"}, {"ar", "Arabic"}, {"hi", "Hindi"},
	{"bn", "Bengali"}, {"ta", "Tamil"}, {"te", "Telugu"}, {"ml", "Malayalam"},
	{"kn", "Kannada"}, {"mr", "Marathi"}, {"gu", "Gujarati"}, {"pa", "Punjabi"},
	{"ur", "Urdu"}, {"fa", "Persian"}, {"tr", "Turkish"}, {"nl", "Dutch"},
	{"pl", "Polish"}, {"uk", "Ukrainian"}, {"sv", "Swedish"}, {"no", "Norwegian"},
	{"da", "Danish"}, {"fi", "Finnish"}, {"cs", "Czech"}, {"el", "Greek"},
	{"he", "Hebrew"}, {"th", "Thai"}, {"vi", "Vietnamese"}, {"id", "Indonesian"},
	{"ms", "Malay"}, {"ro", "Romanian"}, {"hu", "Hungarian"}, {"sw", "Swahili"},
}

func googleTranslate(text, target string) (string, string, error) {
	api := fmt.Sprintf("https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=%s&dt=t&q=%s",
		target, url.QueryEscape(text))
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(api)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result []interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", err
	}
	if len(result) == 0 {
		return "", "", fmt.Errorf("no result")
	}
	chunks, _ := result[0].([]interface{})
	var sb strings.Builder
	for _, c := range chunks {
		if line, ok := c.([]interface{}); ok && len(line) > 0 {
			if s, ok := line[0].(string); ok {
				sb.WriteString(s)
			}
		}
	}
	src := "unknown"
	if len(result) > 2 {
		if s, ok := result[2].(string); ok {
			src = s
		}
	}
	return sb.String(), src, nil
}

func LangsHandler(m *tg.NewMessage) error {
	var sb strings.Builder
	sb.WriteString("<b>Popular Language Codes (ISO 639-1)</b>\n\n")
	for _, l := range popularLangCodes {
		fmt.Fprintf(&sb, "<code>%s</code> - %s\n", l.Code, html.EscapeString(l.Name))
	}
	sb.WriteString("\n<i>Use with /tr &lt;code&gt; replying to a message.</i>")
	m.Reply(sb.String())
	return nil
}

func DetectHandler(m *tg.NewMessage) error {
	text := m.Args()
	if text == "" && m.IsReply() {
		r, _ := m.GetReplyMessage()
		text = r.Text()
	}
	if strings.TrimSpace(text) == "" {
		m.Reply("Provide text or reply to a message: <code>/detect &lt;text&gt;</code>")
		return nil
	}
	translated, code, err := googleTranslate(text, "en")
	if err != nil {
		m.Reply("Detection failed")
		return nil
	}
	name := code
	for _, l := range popularLangCodes {
		if l.Code == code {
			name = l.Name + " (" + code + ")"
			break
		}
	}
	m.Reply(fmt.Sprintf("<b>Detected Language:</b> %s\n\n<b>English:</b>\n<code>%s</code>",
		html.EscapeString(name), html.EscapeString(translated)))
	return nil
}

func TranslateHandler(m *tg.NewMessage) error {
	if !m.IsReply() {
		m.Reply("Reply to a message to translate it")
		return nil
	}
	args := m.Args()
	targetLang := "en"
	replaceMode := false
	if args != "" {
		for _, p := range strings.Fields(args) {
			if p == "-r" {
				replaceMode = true
			} else {
				targetLang = p
			}
		}
	}
	r, _ := m.GetReplyMessage()
	text := r.Text()
	if text == "" {
		m.Reply("No text to translate")
		return nil
	}
	translated, src, err := googleTranslate(text, targetLang)
	if err != nil {
		m.Reply("Translation failed")
		return nil
	}
	if replaceMode && modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "delete") {
		r.Delete()
		m.Delete()
		m.Respond(fmt.Sprintf("<b>Translated from %s:</b>\n%s", src, translated))
	} else {
		m.Reply(fmt.Sprintf("<b>Translated (%s -> %s):</b>\n<code>%s</code>", src, targetLang, translated))
	}
	return nil
}

type autotrConfig struct {
	Enabled bool   `json:"e"`
	Lang    string `json:"l"`
	Min     int    `json:"m"`
}

var (
	autotrBucket = []byte("autotr")
	autotrCache  = make(map[int64]*autotrConfig)
	autotrMu     sync.RWMutex
)

func autotrChatKey(chatID int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(chatID))
	return b
}

func autotrLoad(chatID int64) *autotrConfig {
	autotrMu.RLock()
	if c, ok := autotrCache[chatID]; ok {
		autotrMu.RUnlock()
		return c
	}
	autotrMu.RUnlock()
	cfg := &autotrConfig{Enabled: false, Lang: "en", Min: 4}
	database, err := db.GetDB()
	if err != nil || database == nil {
		return cfg
	}
	_ = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket(autotrBucket)
		if b == nil {
			return nil
		}
		raw := b.Get(autotrChatKey(chatID))
		if raw == nil {
			return nil
		}
		var c autotrConfig
		if err := json.Unmarshal(raw, &c); err == nil {
			if c.Lang == "" {
				c.Lang = "en"
			}
			if c.Min <= 0 {
				c.Min = 4
			}
			cfg = &c
		}
		return nil
	})
	autotrMu.Lock()
	autotrCache[chatID] = cfg
	autotrMu.Unlock()
	return cfg
}

func autotrSave(chatID int64, cfg *autotrConfig) error {
	database, err := db.GetDB()
	if err != nil || database == nil {
		return fmt.Errorf("db unavailable")
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	err = database.Update(func(tx *mongostore.Tx) error {
		b, err := tx.CreateBucketIfNotExists(autotrBucket)
		if err != nil {
			return err
		}
		return b.Put(autotrChatKey(chatID), data)
	})
	if err == nil {
		autotrMu.Lock()
		autotrCache[chatID] = cfg
		autotrMu.Unlock()
	}
	return err
}

func AutoTrHandler(m *tg.NewMessage) error {
	if m.IsPrivate() {
		m.Reply("<b>Auto-translate works in groups only.</b>")
		return nil
	}
	if !modules.IsUserAdmin(m.Client, m.SenderID(), m.ChannelID(), "") {
		return nil
	}
	args := strings.TrimSpace(m.Args())
	cfg := autotrLoad(m.ChatID())
	if args == "" || args == "status" {
		state := "off"
		if cfg.Enabled {
			state = "on"
		}
		m.Reply(fmt.Sprintf("<b>Auto-Translate</b>\n • State: <code>%s</code>\n • Lang: <code>%s</code>\n • Min chars: <code>%d</code>\n\n<i>Usage:</i>\n <code>/autotr on|off</code>\n <code>/autotr lang &lt;iso&gt;</code>\n <code>/autotr min &lt;chars&gt;</code>",
			state, html.EscapeString(cfg.Lang), cfg.Min))
		return nil
	}
	parts := strings.Fields(args)
	switch strings.ToLower(parts[0]) {
	case "on", "enable":
		cfg.Enabled = true
		if err := autotrSave(m.ChatID(), cfg); err != nil {
			m.Reply("<b>Failed to save settings.</b>")
			return nil
		}
		m.Reply(fmt.Sprintf("<b>Auto-translate enabled.</b> Target: <code>%s</code>", html.EscapeString(cfg.Lang)))
	case "off", "disable":
		cfg.Enabled = false
		if err := autotrSave(m.ChatID(), cfg); err != nil {
			m.Reply("<b>Failed to save settings.</b>")
			return nil
		}
		m.Reply("<b>Auto-translate disabled.</b>")
	case "lang", "language":
		if len(parts) < 2 {
			m.Reply("<b>Usage:</b> <code>/autotr lang &lt;iso&gt;</code>")
			return nil
		}
		lang := strings.ToLower(strings.TrimSpace(parts[1]))
		if len(lang) < 2 || len(lang) > 8 {
			m.Reply("<b>Invalid language code.</b>")
			return nil
		}
		cfg.Lang = lang
		if err := autotrSave(m.ChatID(), cfg); err != nil {
			m.Reply("<b>Failed to save settings.</b>")
			return nil
		}
		m.Reply(fmt.Sprintf("<b>Target language set to</b> <code>%s</code>", html.EscapeString(lang)))
	case "min":
		if len(parts) < 2 {
			m.Reply("<b>Usage:</b> <code>/autotr min &lt;chars&gt;</code>")
			return nil
		}
		var n int
		if _, err := fmt.Sscanf(parts[1], "%d", &n); err != nil || n < 1 || n > 4096 {
			m.Reply("<b>Invalid number.</b> Must be between 1 and 4096.")
			return nil
		}
		cfg.Min = n
		if err := autotrSave(m.ChatID(), cfg); err != nil {
			m.Reply("<b>Failed to save settings.</b>")
			return nil
		}
		m.Reply(fmt.Sprintf("<b>Minimum length set to</b> <code>%d</code>", n))
	default:
		m.Reply("<b>Unknown subcommand.</b> Use <code>on</code>, <code>off</code>, <code>lang</code>, <code>min</code>, or <code>status</code>.")
	}
	return nil
}

func AutoTrWatcher(m *tg.NewMessage) error {
	if m.IsPrivate() {
		return nil
	}
	if m.Sender != nil && m.Sender.Bot {
		return nil
	}
	if m.Message != nil && m.Message.ViaBotID != 0 {
		return nil
	}
	text := strings.TrimSpace(m.Text())
	if text == "" {
		return nil
	}
	if t := text; len(t) > 0 && (t[0] == '/' || t[0] == '!' || t[0] == '.') {
		return nil
	}
	cfg := autotrLoad(m.ChatID())
	if !cfg.Enabled {
		return nil
	}
	if len([]rune(text)) < cfg.Min {
		return nil
	}
	translated, src, err := googleTranslate(text, cfg.Lang)
	if err != nil || translated == "" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(src), strings.TrimSpace(cfg.Lang)) {
		return nil
	}
	if strings.TrimSpace(translated) == strings.TrimSpace(text) {
		return nil
	}
	m.Reply(fmt.Sprintf("<blockquote><i>%s→%s</i> %s</blockquote>",
		html.EscapeString(src), html.EscapeString(cfg.Lang), html.EscapeString(translated)))
	return nil
}

type weatherGeocodeResult struct {
	Name      string  `json:"name"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Country   string  `json:"country"`
	Admin1    string  `json:"admin1"`
	Timezone  string  `json:"timezone"`
}

type weatherCurrent struct {
	Time             string  `json:"time"`
	Temperature2m    float64 `json:"temperature_2m"`
	RelativeHumidity int     `json:"relative_humidity_2m"`
	WeatherCode      int     `json:"weather_code"`
	WindSpeed10m     float64 `json:"wind_speed_10m"`
	IsDay            int     `json:"is_day"`
}

type weatherForecastResponse struct {
	Latitude  float64        `json:"latitude"`
	Longitude float64        `json:"longitude"`
	Timezone  string         `json:"timezone"`
	Current   weatherCurrent `json:"current"`
}

func weatherCodeDescription(code int) string {
	switch code {
	case 0:
		return "Clear sky"
	case 1:
		return "Mainly clear"
	case 2:
		return "Partly cloudy"
	case 3:
		return "Overcast"
	case 45, 48:
		return "Fog"
	case 51, 53, 55:
		return "Drizzle"
	case 56, 57:
		return "Freezing drizzle"
	case 61, 63, 65:
		return "Rain"
	case 66, 67:
		return "Freezing rain"
	case 71, 73, 75, 77:
		return "Snow"
	case 80, 81, 82:
		return "Rain showers"
	case 85, 86:
		return "Snow showers"
	case 95, 96, 99:
		return "Thunderstorm"
	}
	return "Unknown"
}

func WeatherHandler(m *tg.NewMessage) error {
	city := strings.TrimSpace(m.Args())
	if city == "" {
		m.Reply("<b>Usage:</b> <code>/weather &lt;city&gt;</code>")
		return nil
	}
	status, _ := m.Reply("Fetching weather for <code>" + html.EscapeString(city) + "</code>...")

	client := &http.Client{Timeout: 30 * time.Second}

	geoResp, err := client.Get(fmt.Sprintf("https://geocoding-api.open-meteo.com/v1/search?name=%s&count=1", url.QueryEscape(city)))
	if err != nil {
		status.Edit("Geocode failed: " + html.EscapeString(err.Error()))
		return nil
	}
	defer geoResp.Body.Close()
	var geoData struct {
		Results []weatherGeocodeResult `json:"results"`
	}
	if err := json.NewDecoder(geoResp.Body).Decode(&geoData); err != nil || len(geoData.Results) == 0 {
		status.Edit("City <code>" + html.EscapeString(city) + "</code> not found.")
		return nil
	}
	geo := &geoData.Results[0]

	forecastResp, err := client.Get(fmt.Sprintf("https://api.open-meteo.com/v1/forecast?latitude=%.4f&longitude=%.4f&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m,is_day&timezone=auto", geo.Latitude, geo.Longitude))
	if err != nil {
		status.Edit("Forecast failed: " + html.EscapeString(err.Error()))
		return nil
	}
	defer forecastResp.Body.Close()
	var forecast weatherForecastResponse
	if err := json.NewDecoder(forecastResp.Body).Decode(&forecast); err != nil {
		status.Edit("Forecast parse failed: " + html.EscapeString(err.Error()))
		return nil
	}

	var locParts []string
	if geo.Name != "" {
		locParts = append(locParts, geo.Name)
	}
	if geo.Admin1 != "" && geo.Admin1 != geo.Name {
		locParts = append(locParts, geo.Admin1)
	}
	if geo.Country != "" {
		locParts = append(locParts, geo.Country)
	}

	var sb strings.Builder
	sb.WriteString("<b>Weather</b>\n\n")
	sb.WriteString("<b>Location:</b> ")
	sb.WriteString(html.EscapeString(strings.Join(locParts, ", ")))
	sb.WriteString("\n")
	sb.WriteString("<b>Condition:</b> ")
	sb.WriteString(html.EscapeString(weatherCodeDescription(forecast.Current.WeatherCode)))
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "<b>Temperature:</b> <code>%.1f°C</code>\n", forecast.Current.Temperature2m)
	fmt.Fprintf(&sb, "<b>Humidity:</b> <code>%d%%</code>\n", forecast.Current.RelativeHumidity)
	fmt.Fprintf(&sb, "<b>Wind:</b> <code>%.1f km/h</code>\n", forecast.Current.WindSpeed10m)
	fmt.Fprintf(&sb, "<b>Coords:</b> <code>%.4f, %.4f</code>\n", geo.Latitude, geo.Longitude)
	if forecast.Timezone != "" {
		sb.WriteString("<b>Timezone:</b> <code>")
		sb.WriteString(html.EscapeString(forecast.Timezone))
		sb.WriteString("</code>\n")
	}
	status.Edit(sb.String())
	return nil
}

func registerMiscHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:imdb", IMDbHandler)
	c.On("callback:imdb:", IMDbCallback)
	c.AddRawHandler(&tg.UpdateBotWidgetQuery{}, imdbWidgetQuery)
	modules.OnCommand(c, "cmd:help", modules.HelpHandle)
	modules.OnCommand(c, "cmd:nightmode", NightModeHandler)
	modules.OnCommand(c, "cmd:tempnote", SaveTempNoteHandler)
	c.On("callback:verify_op_", modules.AdminVerifyCallback)
	c.On("callback:help_back", modules.HelpBackCallback)
	modules.OnCommand(c, "cmd:gban", Gban, tg.CustomFilter(modules.FilterOwner))
	modules.OnCommand(c, "cmd:ungban", Ungban, tg.CustomFilter(modules.FilterOwner))
	modules.OnCommand(c, "cmd:tr", TranslateHandler)
	modules.OnCommand(c, "cmd:langs", LangsHandler)
	modules.OnCommand(c, "cmd:detect", DetectHandler)
	modules.OnCommand(c, "cmd:autotr", AutoTrHandler)
	c.On(tg.OnNewMessage, AutoTrWatcher)
	modules.OnCommand(c, "cmd:weather", WeatherHandler)
}

func init() {
	modules.QueueHandlerRegistration(registerMiscHandlers)
	modules.Mods.AddModule("IMDb", "<code>/imdb &lt;title, ttID or IMDb URL&gt;</code> — search IMDb and view title details.")
}

var imdbState struct {
	once   sync.Once
	client *scraper.Scraper
	err    error
}

var imdbGate = make(chan struct{}, 2)
var imdbSearches = cache.New(time.Hour, 10*time.Minute)

func imdbSearchKey(m *tg.NewMessage) string { return fmt.Sprintf("%d:%d", m.ChatID(), m.ID) }

var imdbIDPattern = regexp.MustCompile(`^tt[0-9]{7,12}$`)
var imdbURLPattern = regexp.MustCompile(`^(?:https?://)?(?:www\.)?imdb\.com/title/(tt[0-9]{7,12})(?:/|\?|$)`)

func imdbClip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func imdbTitleID(query string) string {
	if imdbIDPattern.MatchString(query) {
		return query
	}
	if m := imdbURLPattern.FindStringSubmatch(query); m != nil {
		return m[1]
	}
	return ""
}

func imdbClient(ctx context.Context) (*scraper.Scraper, func(), error) {
	select {
	case imdbGate <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	release := func() { <-imdbGate }
	imdbState.once.Do(func() { imdbState.client, imdbState.err = scraper.New() })
	if imdbState.err != nil {
		release()
		return nil, nil, imdbState.err
	}
	return imdbState.client, release, nil
}

func imdbTextHandler(m *tg.NewMessage) error {
	query := strings.TrimSpace(m.Args())
	if query == "" {
		_, err := m.Reply("Usage: <code>/imdb movie name</code>, <code>/imdb tt0133093</code>, or an IMDb title URL.")
		return err
	}
	if len([]rune(query)) > 200 {
		_, err := m.Reply("Please use a shorter title or an IMDb ID.")
		return err
	}
	status, err := m.Reply("Searching IMDb…")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, release, err := imdbClient(ctx)
	if err != nil {
		_, err = status.Edit("IMDb is unavailable. Please try again shortly.")
		return err
	}
	defer release()
	if id := imdbTitleID(query); id != "" {
		page := imdbSearchPage{owner: m.SenderID(), titleID: id, busy: &sync.Mutex{}}
		if err := showIMDbTitle(ctx, c, status, page); err != nil {
			m.Client.Log.Warn("IMDb details failed: %v", err)
			_, err = status.Edit("IMDb details are temporarily unavailable. Please try again shortly.")
			return err
		}
		return nil
	}
	results, err := c.FastSearch(ctx, query, 6)
	if err != nil {
		m.Client.Log.Warn("IMDb search failed: %v", err)
		_, err = status.Edit("IMDb search failed. Please try again shortly.")
		return err
	}
	if len(results) == 0 {
		_, err = status.Edit("No IMDb titles found for <code>" + html.EscapeString(query) + "</code>.")
		return err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "<b>IMDb results for %s</b>\n\n", html.EscapeString(query))
	keyboard := tg.NewKeyboard()
	for i, result := range results {
		if !imdbIDPattern.MatchString(result.IMDbID) {
			continue
		}
		label := imdbClip(result.Title, 70)
		if result.Year != nil {
			label += fmt.Sprintf(" (%d)", *result.Year)
		}
		fmt.Fprintf(&out, "%d. <b>%s</b>", i+1, html.EscapeString(label))
		if result.TypeText != "" {
			fmt.Fprintf(&out, " — %s", html.EscapeString(result.TypeText))
		}
		out.WriteString("\n")
		keyboard.AddRow(tg.Button.Data(imdbClip(label, 55), fmt.Sprintf("imdb:%d:%s", m.SenderID(), result.IMDbID)))
	}
	page := imdbSearchPage{owner: m.SenderID(), text: out.String(), keyboard: keyboard.Build(), busy: &sync.Mutex{}}
	storeIMDbPage(status, page)
	_, err = status.Edit(page.text, &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: page.keyboard})
	return err
}

func storeIMDbPage(status *tg.NewMessage, page imdbSearchPage) {
	if imdbSearches.ItemCount() >= 1000 {
		imdbSearches.DeleteExpired()
		if imdbSearches.ItemCount() >= 1000 {
			for key := range imdbSearches.Items() {
				imdbSearches.Delete(key)
				break
			}
		}
	}
	imdbSearches.SetDefault(imdbSearchKey(status), page)
}

func IMDbCallback(q *tg.CallbackQuery) error {
	parts := strings.Split(q.DataString(), ":")
	if len(parts) != 3 || (parts[2] != "back" && parts[2] != "prevtitle" && parts[2] != "similar" && parts[2] != "collapse" && !strings.HasPrefix(parts[2], "page") && !imdbIDPattern.MatchString(parts[2])) {
		_, err := q.Answer("Invalid IMDb selection.")
		return err
	}
	owner, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || owner != q.SenderID {
		_, err = q.Answer("Run /imdb to search for your own title.")
		return err
	}
	status, err := q.GetMessage()
	if err != nil {
		return err
	}
	cached, ok := imdbSearches.Get(imdbSearchKey(status))
	if !ok || cached.(imdbSearchPage).owner != owner {
		_, err = q.Answer("Search expired. Run /imdb again.")
		return err
	}
	page := cached.(imdbSearchPage)
	if !page.busy.TryLock() {
		_, err = q.Answer("Still loading your previous selection.")
		return err
	}
	defer page.busy.Unlock()
	// Another callback may have completed between the cache read and TryLock.
	if latest, found := imdbSearches.Get(imdbSearchKey(status)); found {
		page = latest.(imdbSearchPage)
	}
	if parts[2] == "similar" || parts[2] == "collapse" {
		if len(page.details) == 0 {
			_, err = q.Answer("Choose a title first.")
			return err
		}
		page.expanded = parts[2] == "similar"
		_, _ = q.Answer("")
		err = editIMDbCard(context.Background(), status, page.details[page.detailIndex], nil, imdbDetailsKeyboard(page, page.detailIndex))
		if err == nil {
			storeIMDbPage(status, page)
		}
		return err
	}
	if strings.HasPrefix(parts[2], "page") {
		index, parseErr := strconv.Atoi(strings.TrimPrefix(parts[2], "page"))
		if parseErr != nil || index < 0 || index >= len(page.details) {
			_, err = q.Answer("Details expired. Run /imdb again.")
			return err
		}
		_, _ = q.Answer(fmt.Sprintf("Details %d/%d", index+1, len(page.details)))
		err = editIMDbCard(context.Background(), status, page.details[index], nil, imdbDetailsKeyboard(page, index))
		if err == nil {
			page.detailIndex = index
			storeIMDbPage(status, page)
		}
		return err
	}
	if parts[2] == "back" {
		if page.keyboard == nil {
			_, err = q.Answer("No search results to return to.")
			return err
		}
		_, _ = q.Answer("Search results")
		text := page.text
		if status.Photo() != nil {
			text = "<b>IMDb search results</b>\nChoose another title below."
		}
		_, err = status.Edit(text, &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: page.keyboard})
		if err == nil {
			storeIMDbPage(status, imdbResultsPage(page))
		}
		return err
	}
	page, err = imdbNavigateTitle(page, parts[2])
	if err != nil {
		_, err = q.Answer(err.Error())
		return err
	}
	_, _ = q.Answer("Loading IMDb details…")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, release, err := imdbClient(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err = showIMDbTitle(ctx, c, status, page); err != nil {
		status.Client.Log.Warn("IMDb navigation failed: %v", err)
		_, _ = q.Answer("Couldn't load that title. Please try again.")
	}
	return err
}

func formatIMDbDetails(d *scraper.Details) string {
	var out strings.Builder
	title := d.IMDbID
	if d.Title != nil {
		title = *d.Title
	}
	fmt.Fprintf(&out, "<b>%s</b>", html.EscapeString(imdbClip(title, 120)))
	if d.Year != nil {
		fmt.Fprintf(&out, " (%d)", *d.Year)
	}
	out.WriteString("\n\n<b>Overview</b>")
	if d.Type != nil {
		fmt.Fprintf(&out, "\n<b>Type:</b> %s", html.EscapeString(imdbClip(*d.Type, 40)))
	}
	if d.RuntimeMinutes != nil {
		fmt.Fprintf(&out, "\n<b>Runtime:</b> %d min", *d.RuntimeMinutes)
	}
	if d.Certificate != nil {
		fmt.Fprintf(&out, "\n<b>Certificate:</b> %s", html.EscapeString(imdbClip(*d.Certificate, 30)))
	}
	if d.ReleaseDate != nil {
		fmt.Fprintf(&out, "\n<b>Release:</b> %s", html.EscapeString(imdbClip(*d.ReleaseDate, 40)))
	}
	if d.Rating != nil {
		fmt.Fprintf(&out, "\n<b>IMDb:</b> %.1f/10", *d.Rating)
	}
	if d.VoteCount != nil {
		fmt.Fprintf(&out, " (%d votes)", *d.VoteCount)
	}
	if len(d.Genres) > 0 {
		fmt.Fprintf(&out, "\n<b>Genres:</b> %s", html.EscapeString(imdbClip(strings.Join(d.Genres, ", "), 90)))
	}
	if len(d.Languages) > 0 {
		fmt.Fprintf(&out, "\n<b>Languages:</b> %s", html.EscapeString(imdbClip(strings.Join(d.Languages, ", "), 90)))
	}
	if len(d.Countries) > 0 {
		fmt.Fprintf(&out, "\n<b>Countries:</b> %s", html.EscapeString(imdbClip(strings.Join(d.Countries, ", "), 90)))
	}
	if len(d.Directors)+len(d.Writers)+len(d.Stars) > 0 {
		out.WriteString("\n\n<b>Cast and crew</b>")
		for _, group := range []struct {
			label  string
			people []scraper.Person
		}{{"Directors", d.Directors}, {"Writers", d.Writers}, {"Cast", d.Stars}} {
			var names []string
			for _, p := range group.people[:min(3, len(group.people))] {
				names = append(names, p.Name)
			}
			if len(names) > 0 {
				fmt.Fprintf(&out, "\n<b>%s:</b> %s", group.label, html.EscapeString(imdbClip(strings.Join(names, ", "), 120)))
			}
		}
	}
	if d.Plot != nil {
		fmt.Fprintf(&out, "\n\n<b>Storyline</b>\n%s", html.EscapeString(imdbClip(*d.Plot, 500)))
	}
	fmt.Fprintf(&out, "\n\n<a href=\"https://www.imdb.com/title/%s/\">Open on IMDb</a>", d.IMDbID)
	return out.String()
}

func showIMDbTitle(ctx context.Context, c *scraper.Scraper, status *tg.NewMessage, page imdbSearchPage) error {
	id := page.titleID
	d, err := c.GetTitleDetails(ctx, id)
	if err != nil {
		return err
	}
	if d == nil {
		return fmt.Errorf("IMDb title not found: %s", id)
	}
	recs, recErr := c.GetRecommendations(ctx, id)
	if recErr != nil {
		status.Client.Log.Warn("IMDb recommendations unavailable: %v", recErr)
	}
	page.recommendations = imdbRecommendations(id, recs)
	pages, err := imdbCaptionPages(formatIMDbDetails(d))
	if err != nil {
		return err
	}
	page.details = pages
	page.detailIndex = min(page.detailIndex, len(pages)-1)
	artwork, artErr := loadIMDbArtwork(ctx, c, d)
	if artErr != nil {
		status.Client.Log.Warn("IMDb artwork unavailable for %s: %v", id, artErr)
		if status.Photo() != nil {
			// Keep the previous title intact instead of pairing its poster
			// with details for a different title.
			return artErr
		}
	}
	keyboard := imdbDetailsKeyboard(page, page.detailIndex)
	err = editIMDbCard(ctx, status, pages[page.detailIndex], artwork, keyboard)
	if err != nil && len(artwork) > 0 && status.Photo() == nil {
		status.Client.Log.Warn("IMDb media edit failed for %s: %v", id, err)
		err = editIMDbCard(ctx, status, pages[page.detailIndex], nil, keyboard)
	}
	if err == nil {
		storeIMDbPage(status, page)
	}
	return err
}

const (
	browserUA       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	extDefaultLimit = 10 << 20
	extTimeout      = 30 * time.Second
)

// extHTTP keeps the default transport so the extra root CAs from modules/rootcas.go apply.
var extHTTP = &http.Client{Timeout: 2 * time.Minute}

type httpStatusError struct {
	Code int
	Body string
}

func (e *httpStatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Code, e.Body)
	}
	return fmt.Sprintf("HTTP %d", e.Code)
}

func isHTTPStatus(err error, code int) bool {
	se, ok := err.(*httpStatusError)
	return ok && se.Code == code
}

// extFetch performs a request with a browser UA (some hosts 403 Go's default) and a bounded body.
// hdr is key/value pairs; limit <= 0 uses extDefaultLimit.
func extFetch(ctx context.Context, method, target string, body io.Reader, limit int64, hdr ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, extTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := extHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if limit <= 0 {
		limit = extDefaultLimit
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet := strings.TrimSpace(string(data))
		if len(snippet) > 120 || strings.HasPrefix(snippet, "<") {
			snippet = ""
		}
		return nil, &httpStatusError{Code: resp.StatusCode, Body: snippet}
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func extGet(ctx context.Context, target string, hdr ...string) ([]byte, error) {
	return extFetch(ctx, http.MethodGet, target, nil, 0, hdr...)
}

func extGetJSON(ctx context.Context, target string, out any, hdr ...string) error {
	data, err := extFetch(ctx, http.MethodGet, target, nil, 0, append([]string{"Accept", "application/json"}, hdr...)...)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
