package scraper

import (
	"context"
	"fmt"
	"strings"
)

type Person struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type CastMember struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Image *string `json:"image"`
}

type Money struct {
	Amount   int64   `json:"amount"`
	Currency *string `json:"currency"`
}

type BoxOffice struct {
	Budget         *Money `json:"budget"`
	OpeningWeekend *Money `json:"opening_weekend"`
	Domestic       *Money `json:"domestic"`
	Worldwide      *Money `json:"worldwide"`
}

type SeriesInfo struct {
	EpisodeCount *int `json:"episode_count"`
	SeasonCount  *int `json:"season_count"`
}

type Trailer struct {
	ID             string  `json:"id"`
	Name           *string `json:"name"`
	RuntimeSeconds *int    `json:"runtime_seconds"`
}

type Details struct {
	IMDbID              string       `json:"imdb_id"`
	Title               *string      `json:"title"`
	OriginalTitle       *string      `json:"original_title"`
	Type                *string      `json:"type"`
	IsSeries            bool         `json:"is_series"`
	Year                *int         `json:"year"`
	EndYear             *int         `json:"end_year"`
	ReleaseDate         *string      `json:"release_date"`
	ReleaseCountry      *string      `json:"release_country"`
	Rating              *float64     `json:"rating"`
	VoteCount           *int         `json:"vote_count"`
	Metascore           *int         `json:"metascore"`
	Certificate         *string      `json:"certificate"`
	RuntimeMinutes      *int         `json:"runtime_minutes"`
	Plot                *string      `json:"plot"`
	Genres              []string     `json:"genres"`
	Countries           []string     `json:"countries"`
	Languages           []string     `json:"languages"`
	Keywords            []string     `json:"keywords"`
	Directors           []Person     `json:"directors"`
	Writers             []Person     `json:"writers"`
	Creators            []Person     `json:"creators"`
	Stars               []Person     `json:"stars"`
	TopCast             []CastMember `json:"top_cast"`
	ProductionCompanies []string     `json:"production_companies"`
	BoxOffice           *BoxOffice   `json:"box_office"`
	Series              *SeriesInfo  `json:"series"`
	Trailer             *Trailer     `json:"trailer"`
	Poster              *string      `json:"poster"`
	URL                 string       `json:"url"`
}

func (s *Scraper) GetTitleDetails(ctx context.Context, imdbID string) (*Details, error) {
	if v, ok := s.DetailsCache.Get(imdbID); ok {
		if d, ok := v.(*Details); ok {
			return d, nil
		}
	}
	if _, ok := s.DetailsNegCache.Get(imdbID); ok {
		return nil, nil
	}

	url := baseURL + "/title/" + imdbID + "/"
	html, err := s.FetchHTML(ctx, url)
	if err != nil {
		return nil, err
	}
	if html == "" {
		return nil, nil
	}
	nd := extractNextData(html)
	if nd == nil {
		s.DetailsNegCache.SetDefault(imdbID, negSentinel)
		return nil, &ParseError{Detail: "missing __NEXT_DATA__ for " + imdbID}
	}
	d := buildDetailsFromNextData(nd, imdbID, url)
	if d == nil {
		s.DetailsNegCache.SetDefault(imdbID, negSentinel)
		return nil, nil
	}
	s.DetailsCache.SetDefault(imdbID, d)
	return d, nil
}

func buildDetailsFromNextData(data map[string]any, imdbID, url string) *Details {
	pp := walkMap(data, "props", "pageProps")
	if pp == nil {
		return nil
	}
	af := walkMap(pp, "aboveTheFoldData")
	mc := walkMap(pp, "mainColumnData")

	title := walkString(af, "titleText", "text")
	if title == "" {
		title = walkString(af, "originalTitleText", "text")
	}
	originalTitle := walkString(af, "originalTitleText", "text")

	ratings := walkMap(af, "ratingsSummary")
	if ratings == nil {
		ratings = walkMap(mc, "ratingsSummary")
	}
	rating := walkFloat(ratings, "aggregateRating")
	voteCount := walkInt(ratings, "voteCount")

	poster := walkString(af, "primaryImage", "url")
	posterReduced := reducePosterQuality(poster)

	plot := walkString(af, "plot", "plotText", "plainText")
	mediaType := walkString(af, "titleType", "id")
	isSeries := walkBool(af, "titleType", "isSeries")
	runtimeSec := walkInt64(af, "runtime", "seconds")
	certificate := walkString(af, "certificate", "rating")
	metascore := walkInt(af, "metacritic", "metascore", "score")

	year := walkInt(af, "releaseYear", "year")
	endYear := walkInt(af, "releaseYear", "endYear")

	var releaseDate *string
	var releaseCountry *string
	rd := walkMap(af, "releaseDate")
	if rd != nil {
		if yr := walkInt(rd, "year"); yr != nil {
			month := 1
			if m := walkInt(rd, "month"); m != nil {
				month = *m
			}
			day := 1
			if d := walkInt(rd, "day"); d != nil {
				day = *d
			}
			s := fmt.Sprintf("%04d-%02d-%02d", *yr, month, day)
			releaseDate = &s
		}
		if c := walkString(rd, "country", "text"); c != "" {
			releaseCountry = &c
		}
	}

	genres := stringsFromList(walkList(af, "titleGenres", "genres"), "genre", "text")
	keywords := stringsFromList(walkList(af, "keywords", "edges"), "node", "text")
	if len(keywords) > 20 {
		keywords = keywords[:20]
	}
	countries := stringsFromList(walkList(mc, "countriesDetails", "countries"), "text")
	languages := stringsFromList(walkList(mc, "spokenLanguages", "spokenLanguages"), "text")
	productionCompanies := stringsFromList(walkList(af, "production", "edges"), "node", "company", "companyText", "text")

	var directors, writers, stars, creators []Person
	pcv2 := walkList(af, "principalCreditsV2")
	for _, cat := range pcv2 {
		label := strings.ToLower(walkString(cat, "grouping", "text"))
		names := personsFromCredits(walkList(cat, "credits"))
		switch {
		case strings.Contains(label, "director"):
			directors = names
		case strings.Contains(label, "writer"):
			writers = names
		case strings.Contains(label, "star"):
			stars = names
		case strings.Contains(label, "creator"):
			creators = names
		}
	}
	if len(stars) == 0 {
		principal := walkList(mc, "principalCredits")
		for _, cat := range principal {
			if walkString(cat, "category", "id") == "cast" {
				stars = personsFromCredits(walkList(cat, "credits"))
				break
			}
		}
	}

	topCast := extractTopCast(mc)

	trailer := extractTrailer(af)

	box := extractBoxOffice(mc)

	var series *SeriesInfo
	if isSeries {
		series = &SeriesInfo{
			EpisodeCount: walkInt(mc, "episodes", "episodes", "total"),
			SeasonCount:  seasonCount(mc),
		}
	}

	anyPresent := title != "" || rating != nil || year != nil || poster != "" || plot != ""
	if !anyPresent {
		return nil
	}

	var titlePtr, originalPtr, typePtr, plotPtr, certPtr, posterPtr *string
	if title != "" {
		titlePtr = &title
	}
	if originalTitle != "" && originalTitle != title {
		originalPtr = &originalTitle
	}
	if mediaType != "" {
		typePtr = &mediaType
	}
	if plot != "" {
		plotPtr = &plot
	}
	if certificate != "" {
		certPtr = &certificate
	}
	if posterReduced != "" {
		posterPtr = &posterReduced
	}

	var runtimeMin *int
	if runtimeSec != nil && *runtimeSec > 0 {
		v := int((*runtimeSec + 30) / 60)
		runtimeMin = &v
	}

	return &Details{
		IMDbID:              imdbID,
		Title:               titlePtr,
		OriginalTitle:       originalPtr,
		Type:                typePtr,
		IsSeries:            isSeries,
		Year:                year,
		EndYear:             endYear,
		ReleaseDate:         releaseDate,
		ReleaseCountry:      releaseCountry,
		Rating:              rating,
		VoteCount:           voteCount,
		Metascore:           metascore,
		Certificate:         certPtr,
		RuntimeMinutes:      runtimeMin,
		Plot:                plotPtr,
		Genres:              genres,
		Countries:           countries,
		Languages:           languages,
		Keywords:            keywords,
		Directors:           orEmptyPeople(directors),
		Writers:             orEmptyPeople(writers),
		Creators:            orEmptyPeople(creators),
		Stars:               orEmptyPeople(stars),
		TopCast:             topCast,
		ProductionCompanies: productionCompanies,
		BoxOffice:           box,
		Series:              series,
		Trailer:             trailer,
		Poster:              posterPtr,
		URL:                 url,
	}
}

func orEmptyPeople(p []Person) []Person {
	if p == nil {
		return []Person{}
	}
	return p
}

func stringsFromList(list []any, path ...string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		s := walkString(item, path...)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func personsFromCredits(credits []any) []Person {
	out := make([]Person, 0, len(credits))
	for _, c := range credits {
		id := walkString(c, "name", "id")
		name := walkString(c, "name", "nameText", "text")
		if name == "" {
			continue
		}
		out = append(out, Person{ID: id, Name: name})
	}
	return out
}

func extractTopCast(mc map[string]any) []CastMember {
	groups := walkList(mc, "castV2")
	out := make([]CastMember, 0, 4)
	for _, g := range groups {
		credits := walkList(g, "credits")
		for _, c := range credits {
			name := walkString(c, "name", "nameText", "text")
			if name == "" {
				continue
			}
			entry := CastMember{
				ID:   walkString(c, "name", "id"),
				Name: name,
			}
			if img := walkString(c, "name", "primaryImage", "url"); img != "" {
				entry.Image = &img
			}
			out = append(out, entry)
			if len(out) >= 4 {
				return out
			}
		}
		if len(out) > 0 {
			break
		}
	}
	return out
}

func extractTrailer(af map[string]any) *Trailer {
	edges := walkList(af, "primaryVideos", "edges")
	var current *Trailer
	for _, e := range edges {
		node := walkMap(e, "node")
		if node == nil {
			continue
		}
		id := walkString(node, "id")
		if id == "" {
			continue
		}
		name := walkString(node, "name", "value")
		runtime := walkInt(node, "runtime", "value")
		t := &Trailer{ID: id}
		if name != "" {
			t.Name = &name
		}
		if runtime != nil {
			t.RuntimeSeconds = runtime
		}
		if strings.Contains(strings.ToLower(name), "trailer") {
			return t
		}
		if current == nil {
			current = t
		}
	}
	return current
}

func extractBoxOffice(mc map[string]any) *BoxOffice {
	budget := toMoney(walkMap(mc, "productionBudget", "budget"))
	opening := toMoney(walkMap(mc, "openingWeekendGross", "gross", "total"))
	domestic := toMoney(walkMap(mc, "lifetimeGross", "total"))
	worldwide := toMoney(walkMap(mc, "worldwideGross", "total"))
	if budget == nil && opening == nil && domestic == nil && worldwide == nil {
		return nil
	}
	return &BoxOffice{
		Budget:         budget,
		OpeningWeekend: opening,
		Domestic:       domestic,
		Worldwide:      worldwide,
	}
}

func toMoney(m map[string]any) *Money {
	if m == nil {
		return nil
	}
	amt := walkInt64(m, "amount")
	if amt == nil {
		return nil
	}
	cur := walkString(m, "currency")
	out := &Money{Amount: *amt}
	if cur != "" {
		out.Currency = &cur
	}
	return out
}

func seasonCount(mc map[string]any) *int {
	if v := walkInt(mc, "episodes", "seasons"); v != nil {
		return v
	}
	if l := walkList(mc, "episodes", "seasons"); l != nil {
		n := len(l)
		return &n
	}
	return nil
}
