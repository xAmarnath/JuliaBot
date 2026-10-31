package scraper

import (
	"context"
	"regexp"
	"strings"
)

type Recommendation struct {
	IMDbID string  `json:"imdb_id"`
	Title  string  `json:"title"`
	Year   *int    `json:"year"`
	Poster *string `json:"poster"`
}

var (
	moreLikeHeaderRe = regexp.MustCompile(`(?is)<h3[^>]*>\s*More like this\s*</h3>`)
	moreLikeItemRe   = regexp.MustCompile(`(?s)href="/title/(tt\d+)/?[^"]*".*?class="[^"]*(?:ipc-title__text|ipc-poster-card__title-text|ipc-poster-card__title)[^"]*".*?>([^<]+)</span>`)
	yearInSuffixRe   = regexp.MustCompile(`\((\d{4})\)`)
)

func (s *Scraper) GetRecommendations(ctx context.Context, imdbID string) ([]Recommendation, error) {
	if v, ok := s.RecsCache.Get(imdbID); ok {
		if r, ok := v.([]Recommendation); ok {
			return r, nil
		}
	}
	url := baseURL + "/title/" + imdbID + "/"
	body, err := s.FetchHTML(ctx, url)
	if err != nil {
		return nil, err
	}
	if body == "" {
		return nil, nil
	}
	nd := extractNextData(body)
	var recs []Recommendation
	if nd != nil {
		recs = buildRecsFromNextData(nd)
		if len(recs) == 0 {
			recs = buildRecsFromAltPaths(nd)
		}
	}
	if len(recs) == 0 {
		recs = scrapeRecsFromHTML(body)
	}
	if len(recs) == 0 {
		return nil, nil
	}
	s.RecsCache.SetDefault(imdbID, recs)
	return recs, nil
}

func buildRecsFromNextData(nd map[string]any) []Recommendation {
	edges := walkList(nd, "props", "pageProps", "mainColumnData", "moreLikeThisTitles", "edges")
	return recsFromEdges(edges, 10)
}

func buildRecsFromAltPaths(nd map[string]any) []Recommendation {
	pp := walkMap(nd, "props", "pageProps")
	candidates := [][]string{
		{"contentData", "moreLikeThisTitles", "edges"},
		{"aboveTheFoldData", "moreLikeThisTitles", "edges"},
		{"contentData", "section", "moreLikeThisTitles", "edges"},
	}
	for _, path := range candidates {
		if edges := walkList(pp, path...); len(edges) > 0 {
			return recsFromEdges(edges, 10)
		}
	}
	sections := walkList(pp, "mainColumnData", "sections")
	for _, sec := range sections {
		if edges := walkList(sec, "moreLikeThisTitles", "edges"); len(edges) > 0 {
			return recsFromEdges(edges, 10)
		}
	}
	return nil
}

func recsFromEdges(edges []any, limit int) []Recommendation {
	out := make([]Recommendation, 0, limit)
	for _, e := range edges {
		if len(out) >= limit {
			break
		}
		node := walkMap(e, "node")
		if node == nil {
			continue
		}
		id := walkString(node, "id")
		title := walkString(node, "titleText", "text")
		if id == "" || title == "" {
			continue
		}
		rec := Recommendation{IMDbID: id, Title: title}
		if y := walkInt(node, "releaseYear", "year"); y != nil {
			rec.Year = y
		}
		if p := walkString(node, "primaryImage", "url"); p != "" {
			reduced := reducePosterQuality(p)
			rec.Poster = &reduced
		}
		out = append(out, rec)
	}
	return out
}

func scrapeRecsFromHTML(body string) []Recommendation {
	if !moreLikeHeaderRe.MatchString(body) {
		return nil
	}
	matches := moreLikeItemRe.FindAllStringSubmatchIndex(body, -1)
	if matches == nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]Recommendation, 0, 10)
	for _, m := range matches {
		if len(out) >= 10 {
			break
		}
		id := body[m[2]:m[3]]
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		title := strings.TrimSpace(body[m[4]:m[5]])
		if title == "" {
			continue
		}
		rec := Recommendation{IMDbID: id, Title: title}
		tail := body[m[1]:]
		if len(tail) > 200 {
			tail = tail[:200]
		}
		if ym := yearInSuffixRe.FindStringSubmatch(tail); ym != nil {
			if y, err := parseYearInt(ym[1]); err == nil {
				rec.Year = &y
			}
		}
		out = append(out, rec)
	}
	return out
}

func parseYearInt(s string) (int, error) {
	y := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nil
		}
		y = y*10 + int(c-'0')
	}
	return y, nil
}
