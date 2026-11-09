package extras

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"main/internal/imdb/scraper"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	tg "github.com/xAmarnath/gogram/telegram"
)

//go:embed imdb_widget.html
var imdbWidgetHTML string

var cinemaSessions = cache.New(time.Hour, 10*time.Minute)
var cinemaStoreMu sync.Mutex
var cinemaTrailerID = regexp.MustCompile(`^vi[0-9]{1,16}$`)

type cinemaChoice struct {
	Title  string `json:"t"`
	Meta   string `json:"m,omitempty"`
	Action string `json:"a"`
}

type cinemaState struct {
	Revision int            `json:"rev"`
	Mode     string         `json:"mode"`
	Title    string         `json:"title"`
	Meta     string         `json:"meta,omitempty"`
	Rating   string         `json:"rating,omitempty"`
	Votes    string         `json:"votes,omitempty"`
	Body     string         `json:"body,omitempty"`
	Rows     []cinemaChoice `json:"rows,omitempty"`
	Tab      string         `json:"tab,omitempty"`
	Page     int            `json:"page"`
	Pages    int            `json:"pages"`
	ID       string         `json:"id,omitempty"`
	Trailer  string         `json:"trailer,omitempty"`
	Back     bool           `json:"back,omitempty"`
	Poster   bool           `json:"poster,omitempty"`
}

// All budgets are encoded JSON bytes, including escaping, not rune counts.
func cinemaClip(s string, budget int) string {
	r := []rune(strings.ToValidUTF8(strings.TrimSpace(s), "�"))
	if len(r) > budget {
		r = r[:budget]
	}
	for len(r) > 0 {
		b, _ := json.Marshal(string(r))
		if len(b) <= budget {
			return string(r)
		}
		r = r[:len(r)-1]
	}
	return ""
}

func (s cinemaState) JSON() string {
	s.Title, s.Meta = cinemaClip(s.Title, 120), cinemaClip(s.Meta, 95)
	s.Rating, s.Votes = cinemaClip(s.Rating, 20), cinemaClip(s.Votes, 35)
	s.Body = cinemaClip(s.Body, 480)
	s.Rows = append([]cinemaChoice(nil), s.Rows[:min(3, len(s.Rows))]...)
	for i := range s.Rows {
		s.Rows[i].Title = cinemaClip(s.Rows[i].Title, 115)
		s.Rows[i].Meta = cinemaClip(s.Rows[i].Meta, 65)
	}
	b, _ := json.Marshal(s)
	// Keep routing fields intact if optional content fills the remaining budget.
	for len(b) > 1024 {
		if len(s.Body) > 0 {
			s.Body = cinemaClip(s.Body, max(2, len(s.Body)-40))
		} else if len(s.Meta) > 0 {
			s.Meta = ""
		} else {
			for i := range s.Rows {
				s.Rows[i].Title = cinemaClip(s.Rows[i].Title, max(2, len(s.Rows[i].Title)-20))
				s.Rows[i].Meta = ""
			}
		}
		b, _ = json.Marshal(s)
	}
	return string(b)
}

type cinemaPosition struct {
	details *scraper.Details
	recs    []scraper.Recommendation
	tab     string
	page    int
}
type cinemaSession struct {
	mu                         sync.Mutex
	owner                      int64
	status                     *tg.NewMessage
	query                      string
	results                    []scraper.FastSearchItem
	details                    *scraper.Details
	recs                       []scraper.Recommendation
	history                    []cinemaPosition
	tab                        string
	page, resultPage, revision int
	state                      cinemaState
	allowed                    map[string]bool
	posters                    map[string]bool
}

func storeCinema(s *cinemaSession) {
	cinemaStoreMu.Lock()
	defer cinemaStoreMu.Unlock()
	if cinemaSessions.ItemCount() >= 1000 {
		cinemaSessions.DeleteExpired()
		if cinemaSessions.ItemCount() >= 1000 {
			for k := range cinemaSessions.Items() {
				cinemaSessions.Delete(k)
				break
			}
		}
	}
	cinemaSessions.SetDefault(imdbSearchKey(s.status), s)
}

func cinemaHome() []scraper.FastSearchItem {
	return []scraper.FastSearchItem{
		{IMDbID: "tt0133093", Title: "The Matrix", TypeText: "Science fiction · 1999"},
		{IMDbID: "tt0816692", Title: "Interstellar", TypeText: "Adventure · 2014"},
		{IMDbID: "tt0903747", Title: "Breaking Bad", TypeText: "Crime series · 2008–2013"},
		{IMDbID: "tt0111161", Title: "The Shawshank Redemption", TypeText: "Drama · 1994"},
		{IMDbID: "tt0245429", Title: "Spirited Away", TypeText: "Animation · 2001"},
		{IMDbID: "tt6751668", Title: "Parasite", TypeText: "Thriller · 2019"},
	}
}

func IMDbHandler(m *tg.NewMessage) error {
	if !m.IsPrivate() {
		return imdbTextHandler(m)
	}
	query := strings.TrimSpace(m.Args())
	if len([]rune(query)) > 200 {
		_, err := m.Reply("Please use a shorter title or an IMDb ID.")
		return err
	}
	initial := cinemaState{Mode: "loading", Title: "Your next great watch", Body: "Searching IMDb…"}
	status, err := m.ReplyMedia(&tg.InputMediaWidget{Width: 340, Height: 0, AllowQueries: true, Html: imdbWidgetHTML, ChatData: initial.JSON()}, &tg.MediaOptions{Caption: "IMDb cinema · Search with /imdb title"})
	if err != nil {
		if tg.MatchError(err, "INPUT_MEDIA_WIDGET_NOT_ALLOWED") || tg.MatchError(err, "MEDIA_INVALID") {
			return imdbTextHandler(m)
		}
		return err
	}
	s := &cinemaSession{owner: m.SenderID(), status: status, query: query, tab: "overview"}
	s.mu.Lock()
	defer s.mu.Unlock()
	storeCinema(s)
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	if query == "" {
		s.results = cinemaHome()
		return s.publish(ctx)
	}
	c, release, err := imdbClient(ctx)
	if err == nil {
		defer release()
		if id := imdbTitleID(query); id != "" {
			err = s.loadTitle(ctx, c, id, false)
		} else {
			var results []scraper.FastSearchItem
			results, err = c.FastSearch(ctx, query, 12)
			seen := map[string]bool{}
			for _, r := range results {
				if imdbIDPattern.MatchString(r.IMDbID) && !seen[r.IMDbID] {
					seen[r.IMDbID] = true
					s.results = append(s.results, r)
				}
			}
		}
	}
	if err != nil {
		m.Client.Log.Warn("[imdb-widget] initial load failed: %v", err)
		return s.publishError("IMDb is taking a break. Tap Retry to try again.")
	}
	return s.publish(context.Background())
}

func cinemaValue[T any](p *T) string {
	if p == nil {
		return ""
	}
	return fmt.Sprint(*p)
}
func cinemaJoin(parts ...string) string {
	var out []string
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " · ")
}

func cinemaChunks(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return []string{"IMDb has not listed this information yet."}
	}
	var pages []string
	for text != "" {
		part := cinemaClip(text, 460)
		// Widgets cannot scroll. Bound visual lines as well as payload bytes.
		// Conservative columns allow narrow bubbles and wide Unicode glyphs.
		lines, columns := 1, 0
		for i, r := range part {
			width := 1
			if r > 127 || r == 'W' || r == 'M' {
				width = 2
			}
			if r == '\n' {
				lines++
				columns = 0
			} else {
				columns += width
				if columns > 26 {
					lines++
					columns = width
				}
			}
			if lines > 6 {
				part = part[:i]
				break
			}
		}
		if len(part) < len(text) {
			if n := strings.LastIndexAny(part, " \n"); n > len(part)/2 {
				part = part[:n]
			}
		}
		if part == "" {
			break
		}
		pages = append(pages, part)
		text = strings.TrimSpace(text[len(part):])
	}
	return pages
}

func cinemaPeople(d *scraper.Details) string {
	var lines []string
	for _, g := range []struct {
		name   string
		people []scraper.Person
	}{{"Directors", d.Directors}, {"Creators", d.Creators}, {"Writers", d.Writers}, {"Stars", d.Stars}} {
		var names []string
		for _, p := range g.people {
			names = append(names, p.Name)
		}
		if len(names) > 0 {
			lines = append(lines, g.name+"\n"+strings.Join(names, ", "))
		}
	}
	var cast []string
	for _, p := range d.TopCast {
		cast = append(cast, p.Name)
	}
	if len(cast) > 0 {
		lines = append(lines, "Cast\n"+strings.Join(cast, ", "))
	}
	return strings.Join(lines, "\n\n")
}

func cinemaFacts(d *scraper.Details) string {
	var lines []string
	add := func(k, v string) {
		if v != "" {
			lines = append(lines, k+"\n"+v)
		}
	}
	add("Original title", cinemaValue(d.OriginalTitle))
	add("Released", cinemaJoin(cinemaValue(d.ReleaseDate), cinemaValue(d.ReleaseCountry)))
	add("Languages", strings.Join(d.Languages, ", "))
	add("Countries", strings.Join(d.Countries, ", "))
	add("Metascore", cinemaValue(d.Metascore))
	add("Studios", strings.Join(d.ProductionCompanies, ", "))
	if d.Series != nil {
		add("Seasons", cinemaValue(d.Series.SeasonCount))
		add("Episodes", cinemaValue(d.Series.EpisodeCount))
	}
	if d.BoxOffice != nil {
		for _, x := range []struct {
			k string
			m *scraper.Money
		}{{"Budget", d.BoxOffice.Budget}, {"Opening weekend", d.BoxOffice.OpeningWeekend}, {"Domestic gross", d.BoxOffice.Domestic}, {"Worldwide gross", d.BoxOffice.Worldwide}} {
			if x.m != nil {
				add(x.k, fmt.Sprintf("%s %s", cinemaValue(x.m.Currency), commaNumber(x.m.Amount)))
			}
		}
	}
	add("Keywords", strings.Join(d.Keywords, ", "))
	return strings.Join(lines, "\n\n")
}

func commaNumber(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// render constructs both visible state and the exact permitted actions.
func (s *cinemaSession) render() (cinemaState, map[string]bool) {
	v := cinemaState{Revision: s.revision + 1, Mode: "list", Title: "Your next great watch", Page: s.page, Pages: 1}
	a := map[string]bool{}
	if s.details == nil {
		if s.query != "" {
			v.Title = "Results for “" + s.query + "”"
		}
		v.Meta = "A few cinema favourites"
		if s.query != "" {
			v.Meta = fmt.Sprintf("%d titles found", len(s.results))
		}
		v.Body = "Search anything with /imdb title"
		if len(s.results) == 0 {
			v.Title = "No titles found"
			v.Body = "Try a different spelling, an IMDb title URL, or a tt identifier."
		}
		v.Pages = max(1, (len(s.results)+2)/3)
		v.Page = max(0, min(s.page, v.Pages-1))
		for i := v.Page * 3; i < min(len(s.results), v.Page*3+3); i++ {
			r := s.results[i]
			action := fmt.Sprintf("pick%d", i)
			a[action] = true
			v.Rows = append(v.Rows, cinemaChoice{r.Title, cinemaJoin(cinemaValue(r.Year), r.TypeText), action})
		}
	} else {
		d := s.details
		v.Mode, v.ID, v.Tab = "title", d.IMDbID, s.tab
		v.Title = cinemaValue(d.Title)
		if v.Title == "" {
			v.Title = d.IMDbID
		}
		runtime := ""
		if d.RuntimeMinutes != nil {
			runtime = fmt.Sprintf("%d min", *d.RuntimeMinutes)
		}
		v.Meta = cinemaJoin(cinemaValue(d.Year), cinemaValue(d.Type), runtime, cinemaValue(d.Certificate))
		if d.Rating != nil {
			v.Rating = fmt.Sprintf("%.1f", *d.Rating)
		}
		if d.VoteCount != nil {
			v.Votes = commaNumber(int64(*d.VoteCount)) + " votes"
		}
		if d.Trailer != nil && cinemaTrailerID.MatchString(d.Trailer.ID) {
			v.Trailer = d.Trailer.ID
		}
		v.Back = len(s.results) > 0 || len(s.history) > 0
		for _, tab := range []string{"overview", "story", "cast", "facts", "similar"} {
			a[tab] = true
		}
		v.Poster = s.posters[d.IMDbID]
		a["poster"] = !v.Poster
		if v.Back {
			a["back"] = true
		}
		if s.tab == "similar" {
			v.Pages = max(1, (len(s.recs)+1)/2)
			v.Page = max(0, min(s.page, v.Pages-1))
			for i := v.Page * 2; i < min(len(s.recs), v.Page*2+2); i++ {
				r := s.recs[i]
				action := fmt.Sprintf("rec%d", i)
				a[action] = true
				v.Rows = append(v.Rows, cinemaChoice{r.Title, cinemaValue(r.Year), action})
			}
			if len(s.recs) == 0 {
				v.Body = "No recommendations available for this title yet."
			}
		} else {
			body := ""
			switch s.tab {
			case "overview":
				body = strings.Join(d.Genres, " · ") + "\n\n" + imdbClip(cinemaValue(d.Plot), 230)
			case "story":
				body = cinemaValue(d.Plot)
			case "cast":
				body = cinemaPeople(d)
			case "facts":
				body = cinemaFacts(d)
			}
			pages := cinemaChunks(body)
			v.Pages = len(pages)
			v.Page = max(0, min(s.page, v.Pages-1))
			v.Body = pages[v.Page]
		}
	}
	if v.Page > 0 {
		a["prev"] = true
	}
	if v.Page+1 < v.Pages {
		a["next"] = true
	}
	return v, a
}

func (s *cinemaSession) write(ctx context.Context, v cinemaState, allowed map[string]bool) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := s.status.Client.MakeRequest(ctx, &tg.MessagesEditMessageWidgetDataParams{Peer: s.status.Peer, ID: s.status.ID, ChatData: v.JSON()})
	if tg.MatchError(err, "MESSAGE_NOT_MODIFIED") {
		err = nil
	}
	if err == nil {
		s.state, s.allowed, s.revision = v, allowed, v.Revision
		if v.Mode == "list" || v.Mode == "title" {
			s.page = v.Page
		}
		storeCinema(s)
	}
	return err
}
func (s *cinemaSession) publish(ctx context.Context) error {
	v, a := s.render()
	return s.write(ctx, v, a)
}
func (s *cinemaSession) publishError(message string) error {
	return s.write(context.Background(), cinemaState{Revision: s.revision + 1, Mode: "error", Title: "A short intermission", Body: message, Pages: 1}, map[string]bool{"retry": true})
}

func (s *cinemaSession) loadTitle(ctx context.Context, c *scraper.Scraper, id string, history bool) error {
	d, err := c.GetTitleDetails(ctx, id)
	if err != nil {
		return err
	}
	if d == nil {
		return errors.New("title not found")
	}
	if history && s.details != nil {
		s.history = append(s.history, cinemaPosition{s.details, s.recs, s.tab, s.page})
		if len(s.history) > 20 {
			s.history = append([]cinemaPosition(nil), s.history[len(s.history)-20:]...)
		}
	}
	if s.details == nil {
		s.resultPage = s.page
	}
	s.details, s.tab, s.page = d, "overview", 0
	s.recs = nil
	// A full-quality poster cannot fit the widget's 1 KB live state. Send it
	// as a photo replying to the card, once per title in this browsing session.
	if err := s.sendPoster(ctx, c); err != nil {
		s.status.Client.Log.Warn("[imdb-widget] automatic poster unavailable: %v", err)
	}
	return nil
}

func (s *cinemaSession) sendPoster(ctx context.Context, c *scraper.Scraper) error {
	if s.details == nil || s.posters[s.details.IMDbID] {
		return nil
	}
	art, err := loadIMDbArtwork(ctx, c, s.details)
	if err != nil {
		return err
	}
	caption := "<b>" + html.EscapeString(cinemaValue(s.details.Title)) + "</b>"
	caption += "\n<a href=\"https://www.imdb.com/title/" + s.details.IMDbID + "/\">IMDb</a> · Use the cinema card to explore."
	_, err = s.status.ReplyMedia(art, &tg.MediaOptions{Caption: caption, ParseMode: tg.HTML, FileName: "poster.jpg", Upload: &tg.UploadOptions{Ctx: ctx}})
	if err == nil {
		if s.posters == nil {
			s.posters = make(map[string]bool)
		}
		s.posters[s.details.IMDbID] = true
	}
	return err
}

func (s *cinemaSession) act(ctx context.Context, action string) error {
	switch action {
	case "next":
		s.page++
		return nil
	case "prev":
		s.page--
		return nil
	case "back":
		if n := len(s.history); n > 0 {
			p := s.history[n-1]
			s.history = s.history[:n-1]
			s.details, s.recs, s.tab, s.page = p.details, p.recs, p.tab, p.page
		} else {
			s.details = nil
			s.page = s.resultPage
		}
		return nil
	case "overview", "story", "cast", "facts":
		s.tab, s.page = action, 0
		return nil
	}
	c, release, err := imdbClient(ctx)
	if err != nil {
		return err
	}
	defer release()
	switch {
	case action == "similar":
		if s.recs == nil {
			recs, e := c.GetRecommendations(ctx, s.details.IMDbID)
			if e != nil {
				return e
			}
			s.recs = imdbRecommendations(s.details.IMDbID, recs)
		}
		s.tab, s.page = "similar", 0
	case action == "poster":
		err = s.sendPoster(ctx, c)
	case strings.HasPrefix(action, "pick"):
		i, e := strconv.Atoi(strings.TrimPrefix(action, "pick"))
		if e != nil || i < 0 || i >= len(s.results) {
			return errors.New("invalid title")
		}
		err = s.loadTitle(ctx, c, s.results[i].IMDbID, false)
	case strings.HasPrefix(action, "rec") && action != "retry":
		i, e := strconv.Atoi(strings.TrimPrefix(action, "rec"))
		if e != nil || i < 0 || i >= len(s.recs) {
			return errors.New("invalid recommendation")
		}
		err = s.loadTitle(ctx, c, s.recs[i].IMDbID, true)
	case action == "retry":
		if s.details != nil || len(s.results) > 0 {
			return nil
		}
		if id := imdbTitleID(s.query); id != "" {
			err = s.loadTitle(ctx, c, id, false)
		} else if s.query == "" {
			s.results = cinemaHome()
		} else {
			var results []scraper.FastSearchItem
			results, err = c.FastSearch(ctx, s.query, 12)
			seen := map[string]bool{}
			for _, r := range results {
				if imdbIDPattern.MatchString(r.IMDbID) && !seen[r.IMDbID] {
					seen[r.IMDbID] = true
					s.results = append(s.results, r)
				}
			}
		}
	default:
		return errors.New("invalid action")
	}
	return err
}

// Navigation becomes authoritative only after Telegram accepts the new state.
// Keep posters: a delivered poster remains delivered even if a later edit fails.
func (s *cinemaSession) transition(ctx context.Context, action string, publish func() error) error {
	position := cinemaPosition{s.details, s.recs, s.tab, s.page}
	history := append([]cinemaPosition(nil), s.history...)
	results, resultPage := s.results, s.resultPage
	err := s.act(ctx, action)
	if err == nil {
		err = publish()
	}
	if err != nil {
		s.details, s.recs, s.tab, s.page = position.details, position.recs, position.tab, position.page
		s.history, s.results, s.resultPage = history, results, resultPage
	}
	return err
}

func cinemaAuthorize(q *tg.UpdateBotWidgetQuery, s *cinemaSession) (string, string) {
	peer, ok := q.Peer.(*tg.PeerUser)
	if !ok || peer.UserID != s.owner || q.UserID != s.owner {
		return "", "This cinema card belongs to another viewer."
	}
	if _, ok := q.QueryType.(*tg.WidgetQueryTypeData); !ok {
		return "", "Invalid request."
	}
	parts := strings.Split(string(q.Data), ":")
	if len(parts) != 3 || parts[0] != "cinema" {
		return "", "Invalid request."
	}
	rev, err := strconv.Atoi(parts[1])
	if err != nil || rev != s.revision {
		return "", "The card changed. Please tap again."
	}
	if !s.allowed[parts[2]] {
		return "", "That action is no longer available."
	}
	return parts[2], ""
}

func imdbWidgetQuery(update tg.Update, c *tg.Client) error {
	q, ok := update.(*tg.UpdateBotWidgetQuery)
	if !ok || !strings.HasPrefix(string(q.Data), "cinema:") {
		return nil
	}
	answer := func(message string, accepted bool) error {
		data, _ := json.Marshal(map[string]any{"message": message, "ok": accepted})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := c.MakeRequest(ctx, &tg.MessagesSetBotWidgetQueryAnswerParams{QueryID: q.QueryID, Result: string(data)})
		return err
	}
	peer, ok := q.Peer.(*tg.PeerUser)
	if !ok {
		return answer("Open /imdb in a private chat with the bot.", false)
	}
	cached, ok := cinemaSessions.Get(fmt.Sprintf("%d:%d", peer.UserID, q.MsgID))
	if !ok {
		return answer("This session expired. Send /imdb to start again.", false)
	}
	s := cached.(*cinemaSession)
	if !s.mu.TryLock() {
		return answer("Still loading. Please wait a moment.", false)
	}
	defer s.mu.Unlock()
	action, reason := cinemaAuthorize(q, s)
	if reason != "" {
		return answer(reason, false)
	}
	// Acknowledge before any network scrape: Telegram's request deadline is 15s.
	if err := answer("Loading…", true); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	if err := s.transition(ctx, action, func() error { return s.publish(context.Background()) }); err != nil {
		c.Log.Warn("[imdb-widget] %s failed: %v", action, err)
		message := "IMDb could not load that selection. Tap Retry to return, then try again."
		if action == "poster" {
			message = "Poster unavailable or already sent in this chat. Tap Retry to return to the title."
		}
		return s.publishError(message)
	}
	c.Log.Info("[imdb-widget] action=%s state=%s revision=%d", action, s.state.Mode, s.revision)
	return nil
}
