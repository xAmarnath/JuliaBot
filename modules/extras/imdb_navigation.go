package extras

import (
	"fmt"
	"main/internal/imdb/scraper"
	"slices"
	"strings"
	"sync"

	tg "github.com/xAmarnath/gogram/telegram"
)

type imdbTitlePosition struct {
	id       string
	index    int
	expanded bool
}

type imdbSearchPage struct {
	owner           int64
	text            string
	keyboard        *tg.ReplyInlineMarkup
	titleID         string
	details         []imdbCaptionPage
	detailIndex     int
	recommendations []scraper.Recommendation
	expanded        bool
	history         []imdbTitlePosition
	busy            *sync.Mutex
}

// Build a new navigation state; callers commit it only after the edit succeeds.
func imdbNavigateTitle(page imdbSearchPage, selection string) (imdbSearchPage, error) {
	if selection == "prevtitle" {
		if len(page.history) == 0 {
			return page, fmt.Errorf("No previous title to return to.")
		}
		last := page.history[len(page.history)-1]
		page.titleID, page.detailIndex = last.id, last.index
		page.expanded = last.expanded
		page.history = slices.Clone(page.history[:len(page.history)-1])
	} else {
		if !imdbIDPattern.MatchString(selection) {
			return page, fmt.Errorf("Invalid IMDb selection.")
		}
		if page.titleID != "" && page.titleID != selection {
			page.history = append(slices.Clone(page.history), imdbTitlePosition{page.titleID, page.detailIndex, page.expanded})
			if len(page.history) > 50 {
				page.history = slices.Clone(page.history[len(page.history)-50:])
			}
		}
		page.titleID, page.detailIndex = selection, 0
		page.expanded = false
	}
	page.details, page.recommendations = nil, nil
	return page, nil
}

func imdbResultsPage(page imdbSearchPage) imdbSearchPage {
	page.titleID, page.detailIndex = "", 0
	page.expanded = false
	page.details, page.recommendations, page.history = nil, nil, nil
	return page
}

func imdbRecommendations(id string, recommendations []scraper.Recommendation) []scraper.Recommendation {
	var result []scraper.Recommendation
	seen := map[string]bool{id: true}
	for _, rec := range recommendations {
		if seen[rec.IMDbID] || !imdbIDPattern.MatchString(rec.IMDbID) || strings.TrimSpace(rec.Title) == "" {
			continue
		}
		seen[rec.IMDbID] = true
		result = append(result, rec)
		if len(result) == 6 {
			break
		}
	}
	return result
}

func imdbDetailsKeyboard(page imdbSearchPage, index int) *tg.ReplyInlineMarkup {
	kb := tg.NewKeyboard()
	if index > 0 {
		kb.AddRow(tg.Button.Data("Previous details", fmt.Sprintf("imdb:%d:page%d", page.owner, index-1)))
	}
	if index+1 < len(page.details) {
		kb.AddRow(tg.Button.Data("More details", fmt.Sprintf("imdb:%d:page%d", page.owner, index+1)))
	}
	if page.expanded {
		for _, rec := range page.recommendations {
			label := imdbClip(rec.Title, 48)
			if rec.Year != nil {
				label += fmt.Sprintf(" (%d)", *rec.Year)
			}
			kb.AddRow(tg.Button.Data(label, fmt.Sprintf("imdb:%d:%s", page.owner, rec.IMDbID)))
		}
	}
	kb.AddRow(tg.Button.URL("IMDb", "https://www.imdb.com/title/"+page.titleID+"/"))
	if !page.expanded && len(page.recommendations) > 0 {
		kb.AddRow(tg.Button.Data("More like this", fmt.Sprintf("imdb:%d:similar", page.owner)))
	}
	switch {
	case page.expanded:
		kb.AddRow(tg.Button.Data("Go back", fmt.Sprintf("imdb:%d:collapse", page.owner)))
	case len(page.history) > 0:
		kb.AddRow(tg.Button.Data("Go back", fmt.Sprintf("imdb:%d:prevtitle", page.owner)))
	case page.keyboard != nil:
		kb.AddRow(tg.Button.Data("Go back", fmt.Sprintf("imdb:%d:back", page.owner)))
	}
	return kb.Build()
}
