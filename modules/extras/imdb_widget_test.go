package extras

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"main/internal/imdb/scraper"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestCinemaFailedPublishRestoresNavigation(t *testing.T) {
	d := cinemaTestDetails()
	s := &cinemaSession{details: d, tab: "facts", page: 2, resultPage: 1, history: []cinemaPosition{{details: d, tab: "similar", page: 1}}}
	err := s.transition(context.Background(), "back", func() error { return errors.New("edit rejected") })
	if err == nil || s.tab != "facts" || s.page != 2 || len(s.history) != 1 || s.resultPage != 1 {
		t.Fatal("failed state edit changed navigation", s.tab, s.page, len(s.history))
	}
	if err = s.transition(context.Background(), "back", func() error { return nil }); err != nil || s.tab != "similar" || s.page != 1 || len(s.history) != 0 {
		t.Fatal("successful state edit did not commit navigation")
	}
}

func cinemaTestDetails() *scraper.Details {
	title, plot, kind, certificate := "The Matrix", "A hacker discovers the nature of his reality.", "Movie", "R"
	year, minutes, votes, rating := 1999, 136, 2200000, 8.7
	return &scraper.Details{IMDbID: "tt0133093", Title: &title, Plot: &plot, Year: &year, RuntimeMinutes: &minutes, Type: &kind, Certificate: &certificate, Rating: &rating, VoteCount: &votes, Genres: []string{"Action", "Science fiction"}, Trailer: &scraper.Trailer{ID: "vi1032782617"}, Directors: []scraper.Person{{Name: "Lana Wachowski"}}, Stars: []scraper.Person{{Name: "Keanu Reeves"}}}
}

func TestCinemaRenderSamples(t *testing.T) {
	d := cinemaTestDetails()
	d.ReleaseDate = new(string)
	*d.ReleaseDate = "1999-03-31"
	d.Languages = []string{"English", "Japanese", "Chinese"}
	d.Countries = []string{"United States", "Australia"}
	d.ProductionCompanies = []string{"Warner Bros.", "Village Roadshow Pictures"}
	long := strings.Repeat("A story about mystery, adventure and discovery. ", 20)
	d.Plot = &long
	s := &cinemaSession{details: d, results: cinemaHome(), tab: "overview", recs: []scraper.Recommendation{{IMDbID: "tt1375666", Title: "Inception"}, {IMDbID: "tt0816692", Title: "Interstellar"}, {IMDbID: "tt0111161", Title: "The Shawshank Redemption"}}}
	samples := map[string]json.RawMessage{}
	for _, tab := range []string{"overview", "story", "cast", "facts", "similar"} {
		s.tab, s.page = tab, 0
		v, _ := s.render()
		for i := 0; i < v.Pages; i++ {
			s.page = i
			page, _ := s.render()
			if len(page.JSON()) > 1024 || len(strings.Split(page.Body, "\n")) > 6 {
				t.Fatal("page exceeds layout budget", tab, i)
			}
		}
		samples[tab] = json.RawMessage(v.JSON())
	}
	s.details, s.page = nil, 0
	v, _ := s.render()
	samples["list"] = json.RawMessage(v.JSON())
	s.details, s.tab = d, "story"
	title := "A very long international movie title with an even longer subtitle"
	d.Title = &title
	v, _ = s.render()
	samples["long"] = json.RawMessage(v.JSON())
	if dir := os.Getenv("JB_WIDGET_PREVIEW_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(samples)
		if err := os.WriteFile(filepath.Join(dir, "cinema-states.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCinemaPayloadAndUnicode(t *testing.T) {
	var compressed bytes.Buffer
	z, _ := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	_, _ = z.Write([]byte(imdbWidgetHTML))
	_ = z.Close()
	if len(imdbWidgetHTML) > 32768 || compressed.Len() > 4096 {
		t.Fatal("HTML payload exceeds Telegram limit", len(imdbWidgetHTML), compressed.Len())
	}
	t.Logf("IMDb widget: %d raw / %d compressed bytes", len(imdbWidgetHTML), compressed.Len())
	for _, text := range []string{strings.Repeat("电影🙂", 300), strings.Repeat("<>&\"\n\x00", 300), strings.Repeat("a", 3000)} {
		d := cinemaTestDetails()
		d.Title = &text
		d.Plot = &text
		s := &cinemaSession{details: d, results: cinemaHome(), tab: "story", revision: 999999}
		for _, tab := range []string{"overview", "story", "cast", "facts", "similar"} {
			s.tab = tab
			v, _ := s.render()
			data := v.JSON()
			if len(data) > 1024 || !json.Valid([]byte(data)) || !utf8.ValidString(data) {
				t.Fatal("bad state", tab, len(data))
			}
		}
		s.details = nil
		s.query = text
		s.results = []scraper.FastSearchItem{{Title: text, TypeText: text}, {Title: text, TypeText: text}, {Title: text, TypeText: text}}
		v, _ := s.render()
		if len(v.JSON()) > 1024 {
			t.Fatal("oversize list")
		}
		chunks := cinemaChunks(text)
		// Whitespace can be trimmed at page boundaries; no nonspace text is lost.
		normal := func(s string) string { return strings.Join(strings.Fields(s), "") }
		if normal(strings.Join(chunks, "")) != normal(text) {
			t.Fatal("story chunks lost text")
		}
	}
}

func TestCinemaNavigationAndActions(t *testing.T) {
	s := &cinemaSession{results: cinemaHome(), query: "", tab: "overview"}
	v, a := s.render()
	if len(v.Rows) != 3 || v.Pages != 2 || !a["next"] || a["prev"] || a["pick3"] {
		t.Fatal(v, a)
	}
	if err := s.act(context.Background(), "next"); err != nil {
		t.Fatal(err)
	}
	v, a = s.render()
	if v.Page != 1 || !a["pick3"] || a["next"] {
		t.Fatal(v, a)
	}
	s.details = cinemaTestDetails()
	s.resultPage = 1
	s.page = 0
	v, a = s.render()
	if v.Rating != "8.7" || v.Votes != "2,200,000 votes" || !a["poster"] || !a["back"] || !a["similar"] {
		t.Fatal(v, a)
	}
	for _, tab := range []string{"story", "cast", "facts"} {
		if err := s.act(context.Background(), tab); err != nil {
			t.Fatal(err)
		}
		v, _ = s.render()
		if v.Tab != tab || v.Body == "" {
			t.Fatal(v)
		}
	}
	original := s.details
	s.history = []cinemaPosition{{original, nil, "cast", 0}}
	s.details = &scraper.Details{IMDbID: "tt0816692"}
	_ = s.act(context.Background(), "back")
	if s.details != original || s.tab != "cast" {
		t.Fatal("history not restored")
	}
	_ = s.act(context.Background(), "back")
	if s.details != nil || s.page != 1 {
		t.Fatal("search position not restored")
	}
}

func TestCinemaQueryAuthorization(t *testing.T) {
	s := &cinemaSession{owner: 42, revision: 3, allowed: map[string]bool{"pick0": true}}
	q := &tg.UpdateBotWidgetQuery{Peer: &tg.PeerUser{UserID: 42}, UserID: 42, Data: []byte("cinema:3:pick0"), QueryType: &tg.WidgetQueryTypeData{}}
	if a, r := cinemaAuthorize(q, s); a != "pick0" || r != "" {
		t.Fatal(a, r)
	}
	for _, data := range []string{"cinema:2:pick0", "cinema:3:pick99", "cinema:3:tt0133093", "cinema:3:pick0:extra"} {
		q.Data = []byte(data)
		if a, _ := cinemaAuthorize(q, s); a != "" {
			t.Fatal("accepted forged/stale action", data)
		}
	}
	q.Data = []byte("cinema:3:pick0")
	q.UserID = 99
	if a, _ := cinemaAuthorize(q, s); a != "" {
		t.Fatal("wrong viewer accepted")
	}
	q.UserID = 42
	q.Peer = &tg.PeerChat{ChatID: 42}
	if a, _ := cinemaAuthorize(q, s); a != "" {
		t.Fatal("group accepted")
	}
}

func TestCinemaPosterDeliveredState(t *testing.T) {
	s := &cinemaSession{details: cinemaTestDetails(), tab: "overview", posters: map[string]bool{"tt0133093": true}}
	v, allowed := s.render()
	if !v.Poster || allowed["poster"] {
		t.Fatal("a delivered poster must be visible and cannot be sent again")
	}
	// Already-delivered artwork never makes a scraper or Telegram request.
	if err := s.sendPoster(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	s.details = &scraper.Details{IMDbID: "tt0816692"}
	v, allowed = s.render()
	if v.Poster || !allowed["poster"] {
		t.Fatal("a different title must still offer its own poster")
	}
}
