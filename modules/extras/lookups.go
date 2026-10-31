package extras

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	modules "main/modules"
	"math"
	"math/big"
	"math/bits"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

// Wikimedia asks API clients for an identifying UA with contact info.
const wikiUA = "JuliaBot/1.0 (https://github.com/amarnathcjd)"

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

func htmlToText(s string) string {
	return strings.TrimSpace(html.UnescapeString(htmlTagRe.ReplaceAllString(s, "")))
}

func clipRunes(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return strings.TrimSpace(string(r[:n])) + "…"
}

func replyArgOrQuoted(m *tg.NewMessage) string {
	if s := strings.TrimSpace(m.Args()); s != "" {
		return s
	}
	if m.IsReply() {
		if r, err := m.GetReplyMessage(); err == nil && r != nil {
			return strings.TrimSpace(r.Text())
		}
	}
	return ""
}

type wiktionaryDefinition struct {
	Definition string   `json:"definition"`
	Examples   []string `json:"examples"`
}

type wiktionaryEntry struct {
	PartOfSpeech string                 `json:"partOfSpeech"`
	Language     string                 `json:"language"`
	Definitions  []wiktionaryDefinition `json:"definitions"`
}

func fetchWiktionary(word string) ([]wiktionaryEntry, error) {
	var out map[string][]wiktionaryEntry
	err := extGetJSON(context.Background(), "https://en.wiktionary.org/api/rest_v1/page/definition/"+url.PathEscape(word), &out, "User-Agent", wikiUA)
	if err != nil {
		return nil, err
	}
	return out["en"], nil
}

func formatWiktionary(word string, entries []wiktionaryEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b>\n", html.EscapeString(word))
	count := 0
	for _, e := range entries {
		for _, d := range e.Definitions {
			if count >= 5 {
				break
			}
			def := htmlToText(d.Definition)
			if def == "" {
				continue
			}
			count++
			fmt.Fprintf(&b, "\n<b>%d.</b> <i>(%s)</i> %s", count, html.EscapeString(strings.ToLower(e.PartOfSpeech)), html.EscapeString(clipRunes(def, 400)))
			if len(d.Examples) > 0 {
				if ex := htmlToText(d.Examples[0]); ex != "" {
					fmt.Fprintf(&b, "\n   <i>e.g. %s</i>", html.EscapeString(clipRunes(ex, 250)))
				}
			}
		}
	}
	if count == 0 {
		return ""
	}
	fmt.Fprintf(&b, "\n\n<a href=\"https://en.wiktionary.org/wiki/%s\">Wiktionary</a>", url.PathEscape(word))
	return b.String()
}

func DefineHandler(m *tg.NewMessage) error {
	word := replyArgOrQuoted(m)
	if word == "" {
		m.Reply("Usage: <code>/define &lt;word&gt;</code>")
		return nil
	}
	word = clipRunes(word, 80)
	status := modules.NewStatus(m, "Looking up the definition…")
	entries, err := fetchWiktionary(word)
	if isHTTPStatus(err, 404) && strings.ToLower(word) != word {
		word = strings.ToLower(word)
		entries, err = fetchWiktionary(word)
	}
	if err != nil && !isHTTPStatus(err, 404) {
		status.Edit("Couldn't fetch definition: " + html.EscapeString(err.Error()))
		return nil
	}
	text := formatWiktionary(word, entries)
	if text == "" {
		status.Edit("No English definition found for <b>" + html.EscapeString(word) + "</b>")
		return nil
	}
	status.Edit(text, &tg.SendOptions{LinkPreview: false})
	return nil
}

type kanjiLookupResponse struct {
	Kanji        string   `json:"kanji"`
	Grade        int      `json:"grade"`
	StrokeCount  int      `json:"stroke_count"`
	Meanings     []string `json:"meanings"`
	KunReadings  []string `json:"kun_readings"`
	OnReadings   []string `json:"on_readings"`
	NameReadings []string `json:"name_readings"`
	JLPT         int      `json:"jlpt"`
	Unicode      string   `json:"unicode"`
	HeisigEn     string   `json:"heisig_en"`
}

func KanjiLookupHandler(m *tg.NewMessage) error {
	q := strings.TrimSpace(m.Args())
	if q == "" {
		m.Reply("Usage: <code>/kanji &lt;character&gt;</code>")
		return nil
	}
	character := string([]rune(q)[0])
	status := modules.NewStatus(m, "Looking up the kanji…")
	var data kanjiLookupResponse
	err := extGetJSON(context.Background(), "https://kanjiapi.dev/v1/kanji/"+url.PathEscape(character), &data)
	if isHTTPStatus(err, 404) || (err == nil && data.Kanji == "") {
		status.Edit("No kanji found for <b>" + html.EscapeString(character) + "</b>")
		return nil
	}
	if err != nil {
		status.Edit("Couldn't fetch kanji: " + html.EscapeString(err.Error()))
		return nil
	}
	var b strings.Builder
	b.WriteString("<b>" + html.EscapeString(data.Kanji) + "</b>")
	if data.Unicode != "" {
		b.WriteString(" <i>(U+" + html.EscapeString(strings.ToUpper(data.Unicode)) + ")</i>")
	}
	b.WriteString("\n")
	for _, f := range []struct {
		label string
		vals  []string
	}{{"Meanings", data.Meanings}, {"On", data.OnReadings}, {"Kun", data.KunReadings}, {"Name", data.NameReadings}} {
		if len(f.vals) > 0 {
			fmt.Fprintf(&b, "\n<b>%s:</b> %s", f.label, html.EscapeString(strings.Join(f.vals, ", ")))
		}
	}
	fmt.Fprintf(&b, "\n<b>Strokes:</b> %d", data.StrokeCount)
	if data.JLPT > 0 {
		fmt.Fprintf(&b, "\n<b>JLPT:</b> N%d", data.JLPT)
	}
	if data.Grade > 0 {
		fmt.Fprintf(&b, "\n<b>Grade:</b> %d", data.Grade)
	}
	if data.HeisigEn != "" {
		b.WriteString("\n<b>Heisig:</b> " + html.EscapeString(data.HeisigEn))
	}
	status.Edit(b.String())
	return nil
}

type urbanDefinition struct {
	Word       string `json:"word"`
	Definition string `json:"definition"`
	Example    string `json:"example"`
	ThumbsUp   int    `json:"thumbs_up"`
	ThumbsDown int    `json:"thumbs_down"`
	Author     string `json:"author"`
	Permalink  string `json:"permalink"`
}

type urbanState struct {
	Term    string
	Results []urbanDefinition
	Created time.Time
}

var urbanCache sync.Map

const (
	urbanPageSize   = 3
	urbanMaxResults = 10
	urbanTTL        = 30 * time.Minute
)

func urbanFetch(term string) ([]urbanDefinition, error) {
	var out struct {
		List []urbanDefinition `json:"list"`
	}
	if err := extGetJSON(context.Background(), "https://api.urbandictionary.com/v0/define?term="+url.QueryEscape(term), &out); err != nil {
		return nil, err
	}
	if len(out.List) > urbanMaxResults {
		out.List = out.List[:urbanMaxResults]
	}
	return out.List, nil
}

func urbanCleanText(s string) string {
	return strings.TrimSpace(strings.NewReplacer("[", "", "]", "", "\r\n", "\n").Replace(s))
}

func urbanRender(term string, results []urbanDefinition, page int) (string, int) {
	if len(results) == 0 {
		return "<b>No definitions found for</b> <i>" + html.EscapeString(term) + "</i>", 0
	}
	total := len(results)
	pages := (total + urbanPageSize - 1) / urbanPageSize
	page = max(0, min(page, pages-1))
	start := page * urbanPageSize
	end := min(start+urbanPageSize, total)
	var b strings.Builder
	b.WriteString("<b>Urban Dictionary:</b> <i>" + html.EscapeString(term) + "</i>\n")
	for i := start; i < end; i++ {
		d := results[i]
		fmt.Fprintf(&b, "\n<b>%d.</b> 👍 %d  👎 %d\n<blockquote>%s</blockquote>", i+1, d.ThumbsUp, d.ThumbsDown, html.EscapeString(clipRunes(urbanCleanText(d.Definition), 600)))
		if ex := urbanCleanText(d.Example); ex != "" {
			b.WriteString("\n<i>Example:</i>\n<blockquote>" + html.EscapeString(clipRunes(ex, 400)) + "</blockquote>")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\n<i>Page %d / %d</i>", page+1, pages)
	return b.String(), pages
}

// Callback data carries only the page (64-byte limit); the term lives in urbanCache.
func urbanKeyboard(page, pages int) *tg.ReplyInlineMarkup {
	if pages <= 1 {
		return nil
	}
	var row []tg.KeyboardInlineButton
	if page > 0 {
		row = append(row, tg.Button.Data("« Prev", fmt.Sprintf("urban:%d", page-1)))
	}
	if page < pages-1 {
		row = append(row, tg.Button.Data("Next »", fmt.Sprintf("urban:%d", page+1)))
	}
	return tg.NewKeyboard().AddRow(row...).Build()
}

var urbanLastGC time.Time
var urbanGCMu sync.Mutex

func urbanGC() {
	urbanGCMu.Lock()
	if time.Since(urbanLastGC) < 5*time.Minute {
		urbanGCMu.Unlock()
		return
	}
	urbanLastGC = time.Now()
	urbanGCMu.Unlock()
	urbanCache.Range(func(k, v any) bool {
		if st, ok := v.(*urbanState); !ok || time.Since(st.Created) > urbanTTL {
			urbanCache.Delete(k)
		}
		return true
	})
}

func UrbanHandler(m *tg.NewMessage) error {
	term := clipRunes(replyArgOrQuoted(m), 100)
	if term == "" {
		m.Reply("Usage: <code>/urban &lt;term&gt;</code>")
		return nil
	}
	urbanGC()
	results, err := urbanFetch(term)
	if err != nil {
		m.Reply("Couldn't fetch Urban Dictionary: " + html.EscapeString(err.Error()))
		return nil
	}
	if len(results) == 0 {
		m.Reply("<b>No definitions found for</b> <i>" + html.EscapeString(term) + "</i>")
		return nil
	}
	text, pages := urbanRender(term, results, 0)
	opts := &tg.SendOptions{LinkPreview: false}
	if kb := urbanKeyboard(0, pages); kb != nil {
		opts.ReplyMarkup = kb
	}
	sent, err := m.Reply(text, opts)
	if err != nil || sent == nil {
		return nil
	}
	urbanCache.Store(fmt.Sprintf("%d:%d", sent.ChatID(), sent.ID), &urbanState{Term: term, Results: results, Created: time.Now()})
	return nil
}

func UrbanCallback(c *tg.CallbackQuery) error {
	rest := strings.TrimPrefix(c.DataString(), "urban:")
	page, err := strconv.Atoi(rest[strings.LastIndex(rest, ":")+1:])
	if err != nil {
		c.Answer("Bad page.")
		return nil
	}
	v, ok := urbanCache.Load(fmt.Sprintf("%d:%d", c.ChatID, c.MessageID))
	st, _ := v.(*urbanState)
	if !ok || st == nil || time.Since(st.Created) > urbanTTL {
		c.Answer("Session expired. Run /urban again.", &tg.CallbackOptions{Alert: true})
		return nil
	}
	text, pages := urbanRender(st.Term, st.Results, page)
	opts := &tg.SendOptions{LinkPreview: false}
	if kb := urbanKeyboard(page, pages); kb != nil {
		opts.ReplyMarkup = kb
	}
	c.Edit(text, opts)
	c.Answer("")
	return nil
}

type wikiThumbnail struct {
	Source string `json:"source"`
}

type wikiContentURLs struct {
	Page string `json:"page"`
}

type wikiSummaryResponse struct {
	Type         string         `json:"type"`
	Title        string         `json:"title"`
	DisplayTitle string         `json:"displaytitle"`
	Description  string         `json:"description"`
	Extract      string         `json:"extract"`
	Thumbnail    *wikiThumbnail `json:"thumbnail"`
	Originalimg  *wikiThumbnail `json:"originalimage"`
	ContentURLs  struct {
		Desktop wikiContentURLs `json:"desktop"`
		Mobile  wikiContentURLs `json:"mobile"`
	} `json:"content_urls"`
}

func wikiTrimExtract(s string, max int) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "\n"); idx > 0 {
		s = strings.TrimSpace(s[:idx])
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	cut := string(runes[:max])
	if i := strings.LastIndex(cut, " "); i > len(cut)/2 {
		cut = cut[:i]
	}
	return strings.TrimSpace(cut) + "..."
}

func wikiFetchSummary(ctx context.Context, title string) (*wikiSummaryResponse, error) {
	var out wikiSummaryResponse
	err := extGetJSON(ctx, "https://en.wikipedia.org/api/rest_v1/page/summary/"+url.PathEscape(strings.ReplaceAll(title, " ", "_")), &out, "User-Agent", wikiUA)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// wikiResolve maps loose queries ("linux kernal") to an article title via opensearch.
func wikiResolve(ctx context.Context, term string) string {
	var out []json.RawMessage
	err := extGetJSON(ctx, "https://en.wikipedia.org/w/api.php?action=opensearch&limit=1&namespace=0&format=json&search="+url.QueryEscape(term), &out, "User-Agent", wikiUA)
	if err != nil || len(out) < 2 {
		return ""
	}
	var titles []string
	if json.Unmarshal(out[1], &titles) != nil || len(titles) == 0 {
		return ""
	}
	return titles[0]
}

func wikiDownloadThumb(ctx context.Context, src string) (string, error) {
	data, err := extFetch(ctx, "GET", src, nil, 8<<20, "User-Agent", wikiUA)
	if err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(strings.SplitN(src, "?", 2)[0]))
	if ext == "" || len(ext) > 5 {
		ext = ".jpg"
	}
	tmp, err := os.CreateTemp("", "wiki_thumb_*"+ext)
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	if _, err := tmp.Write(data); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func WikiHandler(m *tg.NewMessage) error {
	term := clipRunes(replyArgOrQuoted(m), 200)
	if term == "" {
		m.Reply("<b>Usage:</b> <code>/wiki &lt;term&gt;</code>")
		return nil
	}
	status, err := m.Reply("<i>Searching Wikipedia for <code>" + html.EscapeString(term) + "</code>...</i>")
	if err != nil || status == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	data, err := wikiFetchSummary(ctx, term)
	if isHTTPStatus(err, 404) {
		if t := wikiResolve(ctx, term); t != "" {
			data, err = wikiFetchSummary(ctx, t)
		}
	}
	if isHTTPStatus(err, 404) {
		status.Edit("<b>No Wikipedia article found for</b> <code>" + html.EscapeString(term) + "</code>.")
		return nil
	}
	if err != nil {
		status.Edit("<b>Wikipedia lookup failed:</b> <code>" + html.EscapeString(err.Error()) + "</code>")
		return nil
	}

	title := data.Title
	if title == "" {
		title = term
	}
	pageURL := data.ContentURLs.Desktop.Page
	if pageURL == "" {
		pageURL = "https://en.wikipedia.org/wiki/" + url.PathEscape(strings.ReplaceAll(title, " ", "_"))
	}
	disambig := strings.EqualFold(data.Type, "disambiguation")

	var sb strings.Builder
	sb.WriteString("<b>" + html.EscapeString(title) + "</b>")
	if data.Description != "" {
		sb.WriteString("\n<i>" + html.EscapeString(data.Description) + "</i>")
	}
	sb.WriteString("\n\n")
	if disambig {
		sb.WriteString("<i>This term refers to multiple things. Please be more specific.</i>\n\n")
	}
	if extract := wikiTrimExtract(data.Extract, 700); extract != "" {
		sb.WriteString(html.EscapeString(extract) + "\n\n")
	} else {
		sb.WriteString("<i>No summary available.</i>\n\n")
	}
	sb.WriteString("<a href=\"" + html.EscapeString(pageURL) + "\">Read on Wikipedia</a>")
	out := sb.String()

	thumbURL := ""
	if data.Thumbnail != nil {
		thumbURL = data.Thumbnail.Source
	}
	if thumbURL != "" && !disambig {
		if path, err := wikiDownloadThumb(ctx, thumbURL); err == nil {
			defer os.Remove(path)
			if _, err := modules.TransferReplyMedia(m, path, &tg.MediaOptions{Caption: out}); err == nil {
				status.Delete()
				return nil
			}
		}
	}
	status.Edit(out, &tg.SendOptions{LinkPreview: false})
	return nil
}

func numberFacts(n int64) []string {
	var facts []string
	abs := n
	if abs < 0 {
		abs = -abs
	}
	parity := "even"
	if n%2 != 0 {
		parity = "odd"
	}
	facts = append(facts, fmt.Sprintf("%d is %s.", n, parity))
	if n > 1 && big.NewInt(n).ProbablyPrime(20) {
		facts = append(facts, fmt.Sprintf("%d is a prime number.", n))
	} else if n > 1 {
		facts = append(facts, fmt.Sprintf("Prime factorisation: %s", primeFactors(n)))
	}
	if r := int64(math.Sqrt(float64(abs))); n >= 0 && (r*r == n || (r+1)*(r+1) == n) {
		facts = append(facts, fmt.Sprintf("%d is a perfect square.", n))
	}
	if c := int64(math.Round(math.Cbrt(float64(n)))); c*c*c == n && n != 0 {
		facts = append(facts, fmt.Sprintf("%d is a perfect cube (%d³).", n, c))
	}
	if n > 0 && n&(n-1) == 0 {
		facts = append(facts, fmt.Sprintf("%d is a power of two (2^%d).", n, bits.TrailingZeros64(uint64(n))))
	}
	if n > 1 && n <= 1e12 {
		if s := divisorSum(n); s == n {
			facts = append(facts, fmt.Sprintf("%d is a perfect number.", n))
		} else if s > n {
			facts = append(facts, fmt.Sprintf("%d is an abundant number.", n))
		}
	}
	if isFibonacci(n) {
		facts = append(facts, fmt.Sprintf("%d is a Fibonacci number.", n))
	}
	if s := strconv.FormatInt(abs, 10); len(s) > 1 && s == reverseString(s) {
		facts = append(facts, fmt.Sprintf("%d is a palindrome.", n))
	}
	digitSum := 0
	for _, ch := range strconv.FormatInt(abs, 10) {
		digitSum += int(ch - '0')
	}
	facts = append(facts, fmt.Sprintf("Digit sum: %d", digitSum))
	if n > 0 && n < 4000 {
		facts = append(facts, "Roman numeral: "+toRoman(int(n)))
	}
	facts = append(facts,
		"Binary: "+strconv.FormatInt(n, 2),
		"Hex: 0x"+strings.ToUpper(strconv.FormatInt(n, 16)),
		"Octal: 0o"+strconv.FormatInt(n, 8))
	return facts
}

func primeFactors(n int64) string {
	var parts []string
	for p := int64(2); p*p <= n; p++ {
		k := 0
		for n%p == 0 {
			n /= p
			k++
		}
		if k == 1 {
			parts = append(parts, strconv.FormatInt(p, 10))
		} else if k > 1 {
			parts = append(parts, fmt.Sprintf("%d^%d", p, k))
		}
		if p > 1e6 {
			break
		}
	}
	if n > 1 {
		parts = append(parts, strconv.FormatInt(n, 10))
	}
	return strings.Join(parts, " × ")
}

func divisorSum(n int64) int64 {
	sum := int64(1)
	for i := int64(2); i*i <= n; i++ {
		if n%i == 0 {
			sum += i
			if j := n / i; j != i {
				sum += j
			}
		}
	}
	return sum
}

func isFibonacci(n int64) bool {
	if n < 0 {
		return false
	}
	a, b := int64(0), int64(1)
	for a < n {
		if b > math.MaxInt64-a {
			return false
		}
		a, b = b, a+b
	}
	return a == n
}

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func toRoman(n int) string {
	vals := []int{1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1}
	syms := []string{"M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"}
	var b strings.Builder
	for i, v := range vals {
		for n >= v {
			b.WriteString(syms[i])
			n -= v
		}
	}
	return b.String()
}

func NumFactHandler(m *tg.NewMessage) error {
	arg := strings.TrimSpace(m.Args())
	if arg == "" {
		arg = strconv.Itoa(rand.Intn(1000) + 1)
	}
	n, err := strconv.ParseInt(strings.ReplaceAll(arg, ",", ""), 10, 64)
	if err != nil || n == math.MinInt64 {
		m.Reply("<b>Error:</b> please provide a valid integer.")
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<b>Number Facts: %d</b>\n", n)
	for _, f := range numberFacts(n) {
		b.WriteString("\n• " + html.EscapeString(f))
	}
	m.Reply(b.String())
	return nil
}

type onThisDayEvent struct {
	Text string `json:"text"`
	Year int    `json:"year"`
}

func parseMonthDay(arg string) (int, int, bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" || strings.EqualFold(arg, "today") {
		now := time.Now().UTC()
		return int(now.Month()), now.Day(), true
	}
	for _, layout := range []string{"1/2", "01/02", "1-2", "01-02", "Jan 2", "January 2", "2 Jan", "2 January"} {
		if t, err := time.Parse(layout, arg); err == nil {
			return int(t.Month()), t.Day(), true
		}
	}
	return 0, 0, false
}

func DateFactHandler(m *tg.NewMessage) error {
	month, day, ok := parseMonthDay(m.Args())
	if !ok {
		m.Reply("Usage: <code>/datefact [MM/DD]</code> — e.g. <code>/datefact 03/14</code> or <code>/datefact Mar 14</code> (default: today)")
		return nil
	}
	status := modules.NewStatus(m, "Fetching events for that date…")
	var out struct {
		Events []onThisDayEvent `json:"events"`
	}
	err := extGetJSON(context.Background(), fmt.Sprintf("https://en.wikipedia.org/api/rest_v1/feed/onthisday/events/%02d/%02d", month, day), &out, "User-Agent", wikiUA)
	if err != nil {
		status.Edit("<b>Error:</b> failed to fetch date facts: " + html.EscapeString(err.Error()))
		return nil
	}
	if len(out.Events) == 0 {
		status.Edit("<b>Error:</b> no events found for that date.")
		return nil
	}
	rand.Shuffle(len(out.Events), func(i, j int) { out.Events[i], out.Events[j] = out.Events[j], out.Events[i] })
	label := time.Date(2000, time.Month(month), day, 0, 0, 0, 0, time.UTC).Format("January 2")
	var b strings.Builder
	fmt.Fprintf(&b, "<b>On this day — %s</b>\n", label)
	for _, e := range out.Events[:min(3, len(out.Events))] {
		fmt.Fprintf(&b, "\n<b>%d:</b> %s", e.Year, html.EscapeString(clipRunes(e.Text, 300)))
	}
	status.Edit(b.String())
	return nil
}

var (
	wikiRefRe      = regexp.MustCompile(`(?s)<ref[^>/]*/>|<ref[^>]*>.*?</ref>`)
	wikiTemplateRe = regexp.MustCompile(`\{\{[^{}]*\}\}`)
	wikiLinkRe     = regexp.MustCompile(`\[\[(?:[^|\]]*\|)?([^\]]*)\]\]`)
	wikiCommentRe  = regexp.MustCompile(`(?s)<!--.*?-->`)
)

func cleanWikitext(s string) string {
	s = wikiCommentRe.ReplaceAllString(s, "")
	s = wikiRefRe.ReplaceAllString(s, "")
	for i := 0; i < 5 && strings.Contains(s, "{{"); i++ {
		s = wikiTemplateRe.ReplaceAllString(s, "")
	}
	s = wikiLinkRe.ReplaceAllString(s, "$1")
	s = strings.NewReplacer("'''", "", "''", "", "&nbsp;", " ").Replace(s)
	return strings.Join(strings.Fields(htmlTagRe.ReplaceAllString(s, "")), " ")
}

// parseYearEvents extracts bullet events from a Wikipedia year article's "Events" wikitext,
// prefixing nested bullets with their parent date.
func parseYearEvents(wikitext string) []string {
	var events []string
	parent := ""
	for _, line := range strings.Split(wikitext, "\n") {
		if !strings.HasPrefix(line, "*") {
			continue
		}
		depth := len(line) - len(strings.TrimLeft(line, "*"))
		text := cleanWikitext(strings.TrimLeft(line, "*"))
		if text == "" {
			continue
		}
		if depth == 1 {
			if i := strings.Index(text, " – "); i < 0 && len([]rune(text)) < 25 {
				parent = text
				continue
			}
			parent = ""
			if i := strings.Index(text, " – "); i > 0 {
				parent = text[:i]
			}
		} else if parent != "" {
			text = parent + " – " + text
		}
		if len([]rune(text)) >= 20 {
			events = append(events, text)
		}
	}
	return events
}

func YearFactHandler(m *tg.NewMessage) error {
	arg := strings.TrimSpace(m.Args())
	year, err := strconv.Atoi(arg)
	if arg == "" || err != nil || year < 1 || year > time.Now().Year() {
		m.Reply(fmt.Sprintf("Usage: <code>/yearfact &lt;year&gt;</code> — a year between 1 and %d, e.g. <code>/yearfact 1969</code>", time.Now().Year()))
		return nil
	}
	status := modules.NewStatus(m, "Fetching events from that year…")
	var out struct {
		Parse struct {
			Wikitext string `json:"wikitext"`
		} `json:"parse"`
	}
	endpoint := fmt.Sprintf("https://en.wikipedia.org/w/api.php?action=parse&prop=wikitext&section=1&format=json&formatversion=2&redirects=1&page=%s", url.QueryEscape(yearArticle(year)))
	if err := extGetJSON(context.Background(), endpoint, &out, "User-Agent", wikiUA); err != nil {
		status.Edit("<b>Error:</b> failed to fetch year facts: " + html.EscapeString(err.Error()))
		return nil
	}
	events := parseYearEvents(out.Parse.Wikitext)
	if len(events) == 0 {
		status.Edit(fmt.Sprintf("<b>Error:</b> no events found for %d.", year))
		return nil
	}
	rand.Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })
	var b strings.Builder
	fmt.Fprintf(&b, "<b>Events in %d</b>\n", year)
	for _, e := range events[:min(3, len(events))] {
		b.WriteString("\n• " + html.EscapeString(clipRunes(e, 300)))
	}
	fmt.Fprintf(&b, "\n\n<a href=\"https://en.wikipedia.org/wiki/%s\">More on Wikipedia</a>", url.PathEscape(yearArticle(year)))
	status.Edit(b.String(), &tg.SendOptions{LinkPreview: false})
	return nil
}

func yearArticle(year int) string {
	if year < 1000 {
		return fmt.Sprintf("AD_%d", year)
	}
	return strconv.Itoa(year)
}

type zenQuoteResp struct {
	Q string `json:"q"`
	A string `json:"a"`
}

func RandomFactHandler(m *tg.NewMessage) error {
	status := modules.NewStatus(m, "Finding a fact…")
	var f struct {
		Text      string `json:"text"`
		Source    string `json:"source"`
		SourceURL string `json:"source_url"`
	}
	if err := extGetJSON(context.Background(), "https://uselessfacts.jsph.pl/api/v2/facts/random?language=en", &f); err != nil || f.Text == "" {
		status.Edit("<b>Error:</b> failed to fetch a random fact.")
		return nil
	}
	msg := "<b>Random Fact:</b>\n<i>" + html.EscapeString(f.Text) + "</i>"
	if f.Source != "" {
		if f.SourceURL != "" {
			msg += fmt.Sprintf("\n\n<b>Source:</b> <a href=\"%s\">%s</a>", html.EscapeString(f.SourceURL), html.EscapeString(f.Source))
		} else {
			msg += "\n\n<b>Source:</b> " + html.EscapeString(f.Source)
		}
	}
	status.Edit(msg, &tg.SendOptions{LinkPreview: false})
	return nil
}

func zenQuote(m *tg.NewMessage, endpoint, title string) error {
	var arr []zenQuoteResp
	if err := extGetJSON(context.Background(), endpoint, &arr); err != nil || len(arr) == 0 || arr[0].Q == "" {
		m.Reply("<b>Error:</b> failed to fetch a quote.")
		return nil
	}
	author := arr[0].A
	if author == "" {
		author = "Unknown"
	}
	m.Reply(fmt.Sprintf("<b>%s</b>\n<blockquote>%s</blockquote>\n— <i>%s</i>", title, html.EscapeString(arr[0].Q), html.EscapeString(author)))
	return nil
}

func QuoteDailyHandler(m *tg.NewMessage) error {
	return zenQuote(m, "https://zenquotes.io/api/today", "Quote of the Day")
}

func RandomQuoteHandler(m *tg.NewMessage) error {
	return zenQuote(m, "https://zenquotes.io/api/random", "Random Quote")
}

type ipLookupResult struct {
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Query       string  `json:"query"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
	Reverse     string  `json:"reverse"`
}

func normalizeIPTarget(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			target = u.Host
		}
	}
	if i := strings.IndexAny(target, "/?#"); i > 0 {
		target = target[:i]
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	target = strings.Trim(target, "[]")
	return strings.TrimPrefix(strings.ToLower(target), "www.")
}

func IPLookupHandler(m *tg.NewMessage) error {
	target := normalizeIPTarget(replyArgOrQuoted(m))
	if target == "" || strings.ContainsAny(target, " \n") {
		m.Reply("Usage: <code>/ip &lt;ip or domain&gt;</code>")
		return nil
	}
	status := modules.NewStatus(m, "Looking up the address…")
	var r ipLookupResult
	// ip-api's free tier is HTTP-only.
	api := "http://ip-api.com/json/" + url.PathEscape(target) + "?fields=status,message,query,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,reverse"
	if err := extGetJSON(context.Background(), api, &r); err != nil {
		status.Edit("Lookup failed: " + html.EscapeString(err.Error()))
		return nil
	}
	if r.Status != "success" {
		msg := r.Message
		if msg == "" {
			msg = "invalid query"
		}
		status.Edit(fmt.Sprintf("Lookup failed for <code>%s</code>: %s", html.EscapeString(target), html.EscapeString(msg)))
		return nil
	}

	var sb strings.Builder
	sb.WriteString("<b>IP Lookup</b>\n")
	field := func(label, val string, code bool) {
		if val == "" {
			return
		}
		val = html.EscapeString(val)
		if code {
			val = "<code>" + val + "</code>"
		}
		fmt.Fprintf(&sb, "<b>%s:</b> %s\n", label, val)
	}
	field("Query", r.Query, true)
	if r.Reverse != r.Query {
		field("Reverse", r.Reverse, true)
	}
	if r.Country != "" && r.CountryCode != "" {
		field("Country", fmt.Sprintf("%s (%s)", r.Country, r.CountryCode), false)
	} else {
		field("Country", r.Country, false)
	}
	field("Region", strings.Trim(strings.Join([]string{r.City, r.RegionName}, ", "), " ,"), false)
	field("Zip", r.Zip, false)
	field("Timezone", r.Timezone, false)
	if r.Lat != 0 || r.Lon != 0 {
		fmt.Fprintf(&sb, "<b>Coords:</b> <a href=\"https://maps.google.com/?q=%f,%f\">%.4f, %.4f</a>\n", r.Lat, r.Lon, r.Lat, r.Lon)
	}
	field("ISP", r.ISP, false)
	if r.Org != r.ISP {
		field("Org", r.Org, false)
	}
	field("AS", r.AS, true)
	var flags []string
	if r.Mobile {
		flags = append(flags, "mobile")
	}
	if r.Proxy {
		flags = append(flags, "proxy/vpn")
	}
	if r.Hosting {
		flags = append(flags, "hosting/dc")
	}
	field("Flags", strings.Join(flags, ", "), false)
	status.Edit(sb.String(), &tg.SendOptions{LinkPreview: false})
	return nil
}

func registerLookupHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:define", DefineHandler)
	modules.OnCommand(c, "cmd:kanji", KanjiLookupHandler)
	modules.OnCommand(c, "cmd:urban", UrbanHandler)
	modules.OnCommand(c, "cmd:ud", UrbanHandler)
	c.On("callback:urban:", UrbanCallback)
	modules.OnCommand(c, "cmd:wiki", WikiHandler)
	modules.OnCommand(c, "cmd:numfact", NumFactHandler)
	modules.OnCommand(c, "cmd:datefact", DateFactHandler)
	modules.OnCommand(c, "cmd:yearfact", YearFactHandler)
	modules.OnCommand(c, "cmd:randomfact", RandomFactHandler)
	modules.OnCommand(c, "cmd:randomfact2", RandomFactHandler)
	modules.OnCommand(c, "cmd:quotedaily", QuoteDailyHandler)
	modules.OnCommand(c, "cmd:randomquote", RandomQuoteHandler)
	modules.OnCommand(c, "cmd:ip", IPLookupHandler)
	modules.OnCommand(c, "cmd:iplookup", IPLookupHandler)
}

func init() {
	modules.QueueHandlerRegistration(registerLookupHandlers)
	modules.Mods.AddModule("Lookup", `<b>Lookup</b>

<b>Words</b>
 - <code>/define &lt;word&gt;</code> - dictionary definition (Wiktionary). Ex: <code>/define serendipity</code>
 - <code>/urban &lt;term&gt;</code> (alias <code>/ud</code>) - Urban Dictionary with paging. Ex: <code>/urban yeet</code>
 - <code>/kanji &lt;character&gt;</code> - kanji meanings, readings, JLPT. Ex: <code>/kanji 日</code>
 - <code>/wiki &lt;term&gt;</code> - Wikipedia summary. Ex: <code>/wiki Alan Turing</code>

<b>Facts &amp; quotes</b>
 - <code>/numfact [number]</code> - math facts about a number. Ex: <code>/numfact 28</code>
 - <code>/datefact [MM/DD]</code> - historical events on a date (default today). Ex: <code>/datefact 07/20</code>
 - <code>/yearfact &lt;year&gt;</code> - events from a year. Ex: <code>/yearfact 1969</code>
 - <code>/randomfact</code> - a random fact
 - <code>/randomquote</code> - a random quote
 - <code>/quotedaily</code> - quote of the day

<b>Network</b>
 - <code>/ip &lt;ip or domain&gt;</code> (alias <code>/iplookup</code>) - geolocation, ISP, ASN, proxy/hosting flags. Ex: <code>/ip 1.1.1.1</code>

<i>/define, /urban, /wiki and /ip also work as a reply to a message containing the text.</i>`)
}
