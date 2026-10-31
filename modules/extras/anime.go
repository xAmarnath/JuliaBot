package extras

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	modules "main/modules"
)

var animeClient = &http.Client{Timeout: 20 * time.Second}

const anilistQuery = `query ($search: String, $type: MediaType) {
  Media(search: $search, type: $type, sort: SEARCH_MATCH) {
    idMal siteUrl format status episodes chapters volumes averageScore genres
    title { romaji english native }
    description(asHtml: false)
    coverImage { extraLarge large }
    nextAiringEpisode { episode timeUntilAiring }
  }
}`

type animeEntry struct {
	IDMal        int      `json:"idMal"`
	SiteURL      string   `json:"siteUrl"`
	Format       string   `json:"format"`
	Status       string   `json:"status"`
	Episodes     int      `json:"episodes"`
	Chapters     int      `json:"chapters"`
	Volumes      int      `json:"volumes"`
	AverageScore int      `json:"averageScore"`
	Genres       []string `json:"genres"`
	Title        struct {
		Romaji  string `json:"romaji"`
		English string `json:"english"`
		Native  string `json:"native"`
	} `json:"title"`
	Description string `json:"description"`
	CoverImage  struct {
		ExtraLarge string `json:"extraLarge"`
		Large      string `json:"large"`
	} `json:"coverImage"`
	NextAiringEpisode *struct {
		Episode         int `json:"episode"`
		TimeUntilAiring int `json:"timeUntilAiring"`
	} `json:"nextAiringEpisode"`
}

var animeTagRe = regexp.MustCompile(`<[^>]+>`)

func fetchAniList(ctx context.Context, kind, query string) (*animeEntry, error) {
	body, _ := json.Marshal(map[string]any{
		"query":     anilistQuery,
		"variables": map[string]string{"search": query, "type": strings.ToUpper(kind)},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://graphql.anilist.co", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := animeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Media *animeEntry `json:"Media"`
		} `json:"data"`
		Errors []struct {
			Status int `json:"status"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound || (len(out.Errors) > 0 && out.Errors[0].Status == http.StatusNotFound) {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anilist status %d", resp.StatusCode)
	}
	return out.Data.Media, nil
}

func fetchAnimeImage(ctx context.Context, imgURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imgURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := animeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("image status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 10<<20))
}

func truncateAnime(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := n
	for cut > 0 && r[cut] != ' ' {
		cut--
	}
	if cut == 0 {
		cut = n
	}
	return string(r[:cut]) + "..."
}

func animeHumanize(s string) string {
	s = strings.ReplaceAll(strings.ToLower(s), "_", " ")
	if s == "tv" || s == "ova" || s == "ona" {
		return strings.ToUpper(s)
	}
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

func buildAnimeCaption(e *animeEntry, kind string) string {
	title := strings.TrimSpace(e.Title.English)
	if title == "" {
		title = strings.TrimSpace(e.Title.Romaji)
	}
	if title == "" {
		title = "Unknown"
	}
	synopsis := strings.TrimSpace(html.UnescapeString(animeTagRe.ReplaceAllString(strings.ReplaceAll(e.Description, "<br>", "\n"), "")))
	if synopsis == "" {
		synopsis = "No synopsis available."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b>\n", html.EscapeString(title))
	if alt := strings.TrimSpace(e.Title.Romaji); alt != "" && alt != title {
		fmt.Fprintf(&b, "<i>%s</i>\n", html.EscapeString(alt))
	}
	b.WriteString("\n")
	if e.Format != "" {
		fmt.Fprintf(&b, "<b>Type:</b> %s\n", html.EscapeString(animeHumanize(e.Format)))
	}
	if kind == "anime" {
		if e.Episodes > 0 {
			fmt.Fprintf(&b, "<b>Episodes:</b> %d\n", e.Episodes)
		}
		if e.NextAiringEpisode != nil {
			d := time.Duration(e.NextAiringEpisode.TimeUntilAiring) * time.Second
			fmt.Fprintf(&b, "<b>Next episode:</b> %d in %dd %dh\n", e.NextAiringEpisode.Episode, int(d.Hours())/24, int(d.Hours())%24)
		}
	} else {
		if e.Chapters > 0 {
			fmt.Fprintf(&b, "<b>Chapters:</b> %d\n", e.Chapters)
		}
		if e.Volumes > 0 {
			fmt.Fprintf(&b, "<b>Volumes:</b> %d\n", e.Volumes)
		}
	}
	if e.Status != "" {
		fmt.Fprintf(&b, "<b>Status:</b> %s\n", html.EscapeString(animeHumanize(e.Status)))
	}
	if e.AverageScore > 0 {
		fmt.Fprintf(&b, "<b>Score:</b> %d/100\n", e.AverageScore)
	}
	if len(e.Genres) > 0 {
		fmt.Fprintf(&b, "<b>Genres:</b> %s\n", html.EscapeString(strings.Join(e.Genres, ", ")))
	}
	fmt.Fprintf(&b, "\n<blockquote expandable>%s</blockquote>\n", html.EscapeString(truncateAnime(synopsis, 700)))
	if e.SiteURL != "" {
		fmt.Fprintf(&b, "\n<a href=\"%s\">AniList</a>", html.EscapeString(e.SiteURL))
	}
	if e.IDMal > 0 {
		fmt.Fprintf(&b, " · <a href=\"https://myanimelist.net/%s/%d\">MyAnimeList</a>", kind, e.IDMal)
	}
	return b.String()
}

func handleAnimeLookup(m *tg.NewMessage, kind string) error {
	query := strings.TrimSpace(m.Args())
	if query == "" {
		m.Reply(fmt.Sprintf("Usage: <code>/%s &lt;title&gt;</code>", kind))
		return nil
	}
	status, _ := m.Reply(fmt.Sprintf("Searching %s...", kind))
	reply := func(text string) {
		if status != nil {
			status.Edit(text, &tg.SendOptions{LinkPreview: false})
		} else {
			m.Reply(text)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	entry, err := fetchAniList(ctx, kind, query)
	if err != nil {
		reply("Couldn't reach AniList right now. Please try again in a moment.")
		return nil
	}
	if entry == nil {
		reply("<b>No results for:</b> " + html.EscapeString(query))
		return nil
	}

	caption := buildAnimeCaption(entry, kind)
	imgURL := entry.CoverImage.ExtraLarge
	if imgURL == "" {
		imgURL = entry.CoverImage.Large
	}
	if imgURL != "" {
		if img, ierr := fetchAnimeImage(ctx, imgURL); ierr == nil && len(img) > 0 {
			if status != nil {
				status.Delete()
			}
			modules.TransferReplyMedia(m, img, &tg.MediaOptions{Caption: caption, FileName: kind + ".jpg", MimeType: "image/jpeg"})
			return nil
		}
	}
	reply(caption)
	return nil
}

func AnimeHandler(m *tg.NewMessage) error {
	return handleAnimeLookup(m, "anime")
}

func MangaHandler(m *tg.NewMessage) error {
	return handleAnimeLookup(m, "manga")
}

func registerAnimeHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:anime", AnimeHandler)
	modules.OnCommand(c, "cmd:manga", MangaHandler)
}

func init() {
	modules.QueueHandlerRegistration(registerAnimeHandlers)
	modules.Mods.AddModule("Anime", `<b>Anime &amp; Manga</b>

<code>/anime &lt;title&gt;</code> — look up an anime: type, episodes, next airing episode, status, score, genres and synopsis.
<code>/manga &lt;title&gt;</code> — look up a manga: chapters, volumes, status, score and synopsis.

Data from AniList, with a MyAnimeList link when available.
Example: <code>/anime frieren</code>`)
}
