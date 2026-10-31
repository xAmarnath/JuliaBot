package scraper

import (
	"context"
	"regexp"
	"strconv"
)

type InterestItem struct {
	IMDbID         string   `json:"imdb_id"`
	Title          string   `json:"title"`
	Year           *int     `json:"year"`
	Rating         *float64 `json:"rating"`
	VoteCount      *int     `json:"vote_count"`
	MediaType      *string  `json:"media_type"`
	Certificate    *string  `json:"certificate"`
	RuntimeMinutes *int     `json:"runtime_minutes"`
	Plot           *string  `json:"plot"`
	Poster         *string  `json:"poster"`
}

type InterestResult struct {
	Name           *string        `json:"name"`
	Category       *string        `json:"category"`
	Description    *string        `json:"description"`
	TotalMovies    *int           `json:"total_movies"`
	TotalTV        *int           `json:"total_tv"`
	PopularMovies  []InterestItem `json:"popular_movies"`
	TopRatedMovies []InterestItem `json:"top_rated_movies"`
	PopularTV      []InterestItem `json:"popular_tv"`
	TopRatedTV     []InterestItem `json:"top_rated_tv"`
	ComingSoon     []InterestItem `json:"coming_soon"`
	Results        []InterestItem `json:"results,omitempty"`
}

var interestFallbackRe = regexp.MustCompile(`/title/(tt\d{7,10})/`)

func (s *Scraper) GetInterestTitles(ctx context.Context, interestID string, limit int) (*InterestResult, error) {
	cacheKey := "interest:" + interestID + ":" + strconv.Itoa(limit)
	if v, ok := s.SearchCache.Get(cacheKey); ok {
		if r, ok := v.(*InterestResult); ok {
			return r, nil
		}
	}
	url := baseURL + "/interest/" + interestID + "/"
	body, err := s.FetchHTML(ctx, url)
	if err != nil {
		return nil, err
	}
	if body == "" {
		return nil, nil
	}
	nd := extractNextData(body)
	if nd == nil {
		matches := interestFallbackRe.FindAllStringSubmatch(body, -1)
		seen := make(map[string]struct{})
		var results []InterestItem
		for _, m := range matches {
			if _, ok := seen[m[1]]; ok {
				continue
			}
			seen[m[1]] = struct{}{}
			results = append(results, InterestItem{IMDbID: m[1]})
			if len(results) >= limit {
				break
			}
		}
		if len(results) == 0 {
			return nil, nil
		}
		return &InterestResult{Results: results}, nil
	}

	pp := walkMap(nd, "props", "pageProps")
	interestData := walkMap(pp, "interestData")

	res := &InterestResult{}
	if s := walkString(interestData, "primaryText", "text"); s != "" {
		res.Name = &s
	}
	if s := walkString(interestData, "secondaryText", "text"); s != "" {
		res.Category = &s
	}
	if s := walkString(interestData, "description", "value", "plainText"); s != "" {
		res.Description = &s
	}
	res.TotalMovies = walkInt(pp, "totalNumOfMovies")
	res.TotalTV = walkInt(pp, "totalNumOfTvSeries")

	res.PopularMovies = parseInterestList(walkList(pp, "popularMovies"), limit)
	res.TopRatedMovies = parseInterestList(walkList(pp, "topRatedMovies"), limit)
	res.PopularTV = parseInterestList(walkList(pp, "popularTv"), limit)
	res.TopRatedTV = parseInterestList(walkList(pp, "topRatedTv"), limit)
	res.ComingSoon = parseInterestList(walkList(pp, "comingSoon"), limit)

	s.SearchCache.SetDefault(cacheKey, res)
	return res, nil
}

func parseInterestList(list []any, limit int) []InterestItem {
	out := make([]InterestItem, 0, limit)
	for i, item := range list {
		if i >= limit {
			break
		}
		parsed := parseInterestItem(item)
		if parsed != nil {
			out = append(out, *parsed)
		}
	}
	return out
}

func parseInterestItem(item any) *InterestItem {
	imdbID := walkString(item, "id")
	title := walkString(item, "titleText", "text")
	if title == "" {
		title = walkString(item, "originalTitleText", "text")
	}
	if imdbID == "" || title == "" {
		return nil
	}
	out := &InterestItem{IMDbID: imdbID, Title: title}
	out.Year = walkInt(item, "releaseYear", "year")
	out.Rating = walkFloat(item, "ratingsSummary", "aggregateRating")
	out.VoteCount = walkInt(item, "ratingsSummary", "voteCount")
	if mt := walkString(item, "titleType", "id"); mt != "" {
		out.MediaType = &mt
	}
	if c := walkString(item, "certificate", "rating"); c != "" {
		out.Certificate = &c
	}
	if secs := walkInt64(item, "runtime", "seconds"); secs != nil && *secs > 0 {
		m := int((*secs + 30) / 60)
		out.RuntimeMinutes = &m
	}
	if plot := walkString(item, "plot", "plotText", "plainText"); plot != "" {
		out.Plot = &plot
	}
	if p := walkString(item, "primaryImage", "url"); p != "" {
		reduced := reducePosterQuality(p)
		out.Poster = &reduced
	}
	return out
}
