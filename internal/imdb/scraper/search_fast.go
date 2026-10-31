package scraper

import (
	"context"
	"net/url"
	"strings"

	json "github.com/goccy/go-json"
)

type FastSearchItem struct {
	IMDbID    string  `json:"imdb_id"`
	Title     string  `json:"title"`
	Year      *int    `json:"year"`
	YearRange *string `json:"year_range"`
	Type      string  `json:"type"`
	TypeText  string  `json:"type_text"`
	Rank      *int    `json:"rank"`
	Subtitle  *string `json:"subtitle"`
	Poster    *string `json:"poster"`
}

type suggestImage struct {
	ImageURL string `json:"imageUrl"`
}

type suggestEntry struct {
	ID   string       `json:"id"`
	L    string       `json:"l"`
	Y    *int         `json:"y"`
	Yr   *string      `json:"yr"`
	Qid  string       `json:"qid"`
	Q    string       `json:"q"`
	Rank *int         `json:"rank"`
	S    string       `json:"s"`
	I    suggestImage `json:"i"`
}

type suggestResponse struct {
	D []suggestEntry `json:"d"`
}

func (s *Scraper) FastSearch(ctx context.Context, query string, limit int) ([]FastSearchItem, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil, nil
	}
	first := "x"
	if r := firstRune(q); isAlnum(r) {
		first = string(r)
	}
	target := "https://v3.sg.media-imdb.com/suggestion/" + first + "/" + url.QueryEscape(q) + ".json"
	body, err := s.FetchJSON(ctx, target)
	if err != nil {
		return nil, err
	}
	if body == "" {
		return nil, nil
	}
	var resp suggestResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, nil
	}
	results := make([]FastSearchItem, 0, limit)
	for _, e := range resp.D {
		if !strings.HasPrefix(e.ID, "tt") {
			continue
		}
		poster := reducePosterQuality(e.I.ImageURL)
		var posterPtr *string
		if poster != "" {
			posterPtr = &poster
		}
		sub := e.S
		subtitle := &sub
		results = append(results, FastSearchItem{
			IMDbID:    e.ID,
			Title:     e.L,
			Year:      e.Y,
			YearRange: e.Yr,
			Type:      e.Qid,
			TypeText:  e.Q,
			Rank:      e.Rank,
			Subtitle:  subtitle,
			Poster:    posterPtr,
		})
		if len(results) >= limit {
			break
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

func firstRune(s string) rune {
	for _, r := range s {
		return r
	}
	return 0
}
