package scraper

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

type SearchResult struct {
	IMDbID string   `json:"imdb_id"`
	TMDbID *int     `json:"tmdb_id"`
	Type   string   `json:"type"`
	Title  string   `json:"title"`
	Year   *int     `json:"year"`
	Rating *float64 `json:"rating"`
	Poster *string  `json:"poster"`
}

var (
	ttReSimple    = regexp.MustCompile(`/title/(tt\d+)/`)
	ttReFind      = regexp.MustCompile(`/title/(tt\d{7,10})/`)
	numPrefixRe   = regexp.MustCompile(`^\d+\.\s+`)
	viPosterRe    = regexp.MustCompile(`\._V1_.*`)
	ariaLabelRe   = regexp.MustCompile(`^View title page for (.+)$`)
	ratingAriaRe  = regexp.MustCompile(`([\d.]+)`)
	tvKindRe      = regexp.MustCompile(`\b(TV Series|TV Mini Series|TV Special|TV Movie|TV Episode|Series)\b`)
	digitPrefixRe = regexp.MustCompile(`^\d{4}`)
)

var (
	itemSel       = cascadia.MustCompile("li.ipc-metadata-list-summary-item")
	linkSel       = cascadia.MustCompile("a.ipc-title-link-wrapper")
	linkFallSel   = cascadia.MustCompile("a[href*='/title/tt']")
	overlaySel    = cascadia.MustCompile("a.ipc-lockup-overlay[aria-label]")
	titleTextSel  = cascadia.MustCompile(".ipc-title__text")
	yearSel       = cascadia.MustCompile("ul li.dli-title-metadata-item, li[role='presentation']")
	ratingSel     = cascadia.MustCompile("span.ipc-rating-star--rating")
	ratingAriaSel = cascadia.MustCompile("[aria-label]")
	posterSel     = cascadia.MustCompile("img.ipc-image")
	posterFallSel = cascadia.MustCompile("img")
)

func (s *Scraper) GetIMDbID(ctx context.Context, title string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(title))
	if v, ok := s.SearchCache.Get(key); ok {
		if id, ok := v.(string); ok {
			return id, nil
		}
	}
	if _, ok := s.SearchNegCache.Get(key); ok {
		return "", nil
	}
	searchURL := baseURL + "/find/?q=" + url.QueryEscape(title) + "&s=tt"
	body, err := s.FetchHTML(ctx, searchURL)
	if err != nil {
		return "", err
	}
	if body == "" {
		return "", nil
	}
	m := ttReFind.FindStringSubmatch(body)
	if m == nil {
		s.SearchNegCache.SetDefault(key, negSentinel)
		return "", nil
	}
	imdbID := m[1]
	s.SearchCache.SetDefault(key, imdbID)
	return imdbID, nil
}

type AdvancedSearchArgs struct {
	Title     string
	TitleType string
	Countries string
	Genres    string
	Keywords  string
	Languages string
	YearMin   int
	YearMax   int
	Sort      string
}

func (s *Scraper) AdvancedSearch(ctx context.Context, args AdvancedSearchArgs) ([]SearchResult, error) {
	params := url.Values{}
	if args.Title != "" {
		params.Set("title", args.Title)
	}
	if args.TitleType != "" {
		params.Set("title_type", args.TitleType)
	} else {
		params.Set("title_type", "feature,tv_series,tv_miniseries,tv_movie,short,tv_episode")
	}
	if args.Countries != "" {
		params.Set("countries", args.Countries)
	}
	if args.Genres != "" {
		params.Set("genres", args.Genres)
	}
	if args.Keywords != "" {
		params.Set("keywords", args.Keywords)
	}
	if args.Languages != "" {
		params.Set("languages", args.Languages)
	}
	if args.YearMin > 0 {
		params.Set("release_date.gte", strconv.Itoa(args.YearMin)+"-01-01")
	}
	if args.YearMax > 0 {
		params.Set("release_date.lte", strconv.Itoa(args.YearMax)+"-12-31")
	}
	if args.Sort != "" {
		params.Set("sort", args.Sort)
	}
	searchURL := baseURL + "/search/title/?" + params.Encode()
	body, err := s.FetchHTML(ctx, searchURL)
	if err != nil {
		return nil, err
	}
	if body == "" {
		return nil, nil
	}
	return parseAdvancedSearch(body), nil
}

func parseAdvancedSearch(htmlText string) []SearchResult {
	doc, err := html.Parse(strings.NewReader(htmlText))
	if err != nil {
		return nil
	}
	items := cascadia.QueryAll(doc, itemSel)
	seen := make(map[string]struct{})
	results := make([]SearchResult, 0, len(items))
	for _, item := range items {
		link := cascadia.Query(item, linkSel)
		if link == nil {
			link = cascadia.Query(item, linkFallSel)
		}
		if link == nil {
			continue
		}
		href := getAttr(link, "href")
		m := ttReSimple.FindStringSubmatch(href)
		if m == nil {
			continue
		}
		imdbID := m[1]
		if _, ok := seen[imdbID]; ok {
			continue
		}
		seen[imdbID] = struct{}{}

		var title string
		if ov := cascadia.Query(item, overlaySel); ov != nil {
			aria := getAttr(ov, "aria-label")
			if am := ariaLabelRe.FindStringSubmatch(aria); am != nil {
				title = strings.TrimSpace(am[1])
			}
		}
		if title == "" {
			if t := cascadia.Query(item, titleTextSel); t != nil {
				title = strings.TrimSpace(textContent(t))
				title = numPrefixRe.ReplaceAllString(title, "")
			}
		}
		if title == "" {
			continue
		}

		var year *int
		for _, li := range cascadia.QueryAll(item, yearSel) {
			txt := strings.TrimSpace(textContent(li))
			if digitPrefixRe.MatchString(txt) {
				if y, err := strconv.Atoi(txt[:4]); err == nil {
					year = &y
					break
				}
			}
		}

		var rating *float64
		if r := cascadia.Query(item, ratingSel); r != nil {
			if v, err := strconv.ParseFloat(strings.TrimSpace(textContent(r)), 64); err == nil {
				rating = &v
			}
		}
		if rating == nil {
			for _, el := range cascadia.QueryAll(item, ratingAriaSel) {
				aria := getAttr(el, "aria-label")
				if strings.HasPrefix(aria, "IMDb rating") {
					if rm := ratingAriaRe.FindStringSubmatch(aria); rm != nil {
						if v, err := strconv.ParseFloat(rm[1], 64); err == nil {
							rating = &v
						}
					}
					break
				}
			}
		}

		var poster *string
		if img := cascadia.Query(item, posterSel); img != nil {
			src := getAttr(img, "src")
			if strings.HasPrefix(src, "https://m.media-amazon.com/images/") {
				p := viPosterRe.ReplaceAllString(src, "._V1_.jpg")
				poster = &p
			}
		}
		if poster == nil {
			if img := cascadia.Query(item, posterFallSel); img != nil {
				src := getAttr(img, "src")
				if strings.HasPrefix(src, "https://m.media-amazon.com/images/") {
					p := viPosterRe.ReplaceAllString(src, "._V1_.jpg")
					poster = &p
				}
			}
		}
		if poster == nil || strings.HasSuffix(*poster, "null") {
			continue
		}

		contentType := "feature"
		if tvKindRe.MatchString(nodeHTML(item)) {
			contentType = "tv_series"
		}

		results = append(results, SearchResult{
			IMDbID: imdbID,
			Type:   contentType,
			Title:  title,
			Year:   year,
			Rating: rating,
			Poster: poster,
		})
	}
	return results
}

func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func textContent(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

func nodeHTML(n *html.Node) string {
	var b strings.Builder
	html.Render(&b, n)
	return b.String()
}
