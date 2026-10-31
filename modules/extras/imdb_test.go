package extras

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"main/internal/imdb/scraper"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestIMDbInputsAndRendering(t *testing.T) {
	for _, s := range []string{"tt0133093", "https://www.imdb.com/title/tt0133093/?ref_=a"} {
		if imdbTitleID(s) != "tt0133093" {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"https://evil.test/title/tt0133093", "tt1", "The Matrix"} {
		if imdbTitleID(s) != "" {
			t.Fatal(s)
		}
	}
	title, plot := "<movie>", "a & b"
	text := formatIMDbDetails(&scraper.Details{IMDbID: "tt0133093", Title: &title, Plot: &plot})
	if !strings.Contains(text, "&lt;movie&gt;") || !strings.Contains(text, "a &amp; b") {
		t.Fatal(text)
	}
	if !strings.Contains(text, "<b>Overview</b>") || !strings.Contains(text, "<b>Storyline</b>") || strings.Contains(text, "More like this") {
		t.Fatal(text)
	}
}
func TestIMDbLive(t *testing.T) {
	if os.Getenv("JB_IMDB_TEST") != "1" {
		t.Skip("JB_IMDB_TEST not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, release, e := imdbClient(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	results, e := c.FastSearch(ctx, "The Matrix", 6)
	if e != nil || len(results) == 0 {
		t.Fatal("search", e)
	}
	details, e := c.GetTitleDetails(ctx, "tt0133093")
	if e != nil || details == nil || details.Title == nil {
		t.Fatal("details", e)
	}
	t.Logf("IMDb search=%d titles; detail=%s", len(results), *details.Title)
	if details.Poster == nil {
		t.Fatal("title has no poster")
	}
	artwork, e := downloadIMDbArtwork(ctx, *details.Poster)
	if e != nil || len(artwork) == 0 {
		t.Fatal("poster", e)
	}
	t.Logf("IMDb artwork downloaded: %d bytes", len(artwork))
	recs, e := c.GetRecommendations(ctx, "tt0133093")
	if e != nil || len(recs) == 0 {
		t.Fatal("recommendations", e)
	}
	t.Logf("IMDb recommendations=%d", len(recs))
}

func TestIMDbArtwork(t *testing.T) {
	for _, raw := range []string{"file:///tmp/image", "https://evil.test/poster.jpg", "https://m.media-amazon.com.evil.test/x", "https://user@m.media-amazon.com/x"} {
		if imdbArtworkURL(raw) != "" {
			t.Fatal(raw)
		}
	}
	u := imdbArtworkURL("https://m.media-amazon.com/images/M/test._V1_SX300.jpg")
	if !strings.HasSuffix(u, "._V1_QL85_UX1000_.jpg") {
		t.Fatal(u)
	}
	images := &scraper.ImagesResult{Images: []scraper.Image{{URL: "still.jpg"}}}
	if got := imdbImageCandidates(images); len(got) != 1 || got[0] != "still.jpg" {
		t.Fatal(got)
	}
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	var buf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	img.Set(1, 1, color.White)
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	http.DefaultTransport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(buf.Bytes())), Header: make(http.Header), Request: r}, nil
	})
	if data, err := downloadIMDbArtwork(context.Background(), u); err != nil || len(data) == 0 {
		t.Fatal(err)
	}
	http.DefaultTransport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<html>Error</html>")), Header: make(http.Header), Request: r}, nil
	})
	if _, err := downloadIMDbArtwork(context.Background(), u); err == nil {
		t.Fatal("accepted error HTML as artwork")
	}
}

func TestIMDbCaptionPagesPreserveDetailsAndEntities(t *testing.T) {
	title, plot := "Movie <&> 😀", strings.Repeat("Long storyline 😀 & < > ", 100)
	details := &scraper.Details{IMDbID: "tt0133093", Title: &title, Plot: &plot}
	formatted := formatIMDbDetails(details)
	// Also exercise a link crossing a page boundary and a supplementary
	// character at the limit, beyond the normal formatter's shorter fields.
	formatted += "\n<b>" + strings.Repeat("x", 1023) + "😀</b>\n<a href=\"https://www.imdb.com/title/tt0133093/\">" + strings.Repeat("link 😀 ", 250) + "</a>"
	plain, _, err := tg.ParseHTMLToTags(formatted)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := imdbCaptionPages(formatted)
	if err != nil || len(pages) < 2 {
		t.Fatal(len(pages), err)
	}
	var joined strings.Builder
	links, bold := 0, 0
	for _, page := range pages {
		length := len(utf16.Encode([]rune(page.text)))
		if length > 1024 || length == 0 || strings.ContainsRune(page.text, '\ufffd') {
			t.Fatalf("invalid caption length/content: %d", length)
		}
		joined.WriteString(page.text)
		for _, entity := range page.entities {
			var start, count int32
			switch e := entity.(type) {
			case *tg.MessageEntityBold:
				start, count = e.Offset, e.Length
				bold++
			case *tg.MessageEntityTextURL:
				start, count = e.Offset, e.Length
				links++
				if !strings.HasPrefix(e.URL, "https://www.imdb.com/title/") {
					t.Fatal(e.URL)
				}
			default:
				t.Fatalf("unexpected entity %T", entity)
			}
			if start < 0 || count <= 0 || int(start+count) > length {
				t.Fatalf("entity exceeds caption: %d %d %d", start, count, length)
			}
		}
	}
	if joined.String() != plain || links < 3 || bold == 0 {
		t.Fatal("details or formatting lost across pages")
	}
}

type imdbEditRecorder struct {
	calls   int
	text    any
	options *tg.SendOptions
	err     error
}

func (f *imdbEditRecorder) Edit(text any, opts ...*tg.SendOptions) (*tg.NewMessage, error) {
	f.calls++
	f.text, f.options = text, opts[0]
	return nil, f.err
}

func TestIMDbArtworkEditsOriginalMessage(t *testing.T) {
	pages, err := imdbCaptionPages("<b>Movie &amp; details</b>")
	if err != nil {
		t.Fatal(err)
	}
	state := imdbSearchPage{owner: 123, titleID: "tt0133093", details: pages}
	keyboard := imdbDetailsKeyboard(state, 0)
	status := &imdbEditRecorder{}
	artwork := []byte("test-image")
	if err := editIMDbCard(context.Background(), status, pages[0], artwork, keyboard); err != nil {
		t.Fatal(err)
	}
	if status.calls != 1 || status.text != "Movie & details" || !bytes.Equal(status.options.Media.([]byte), artwork) || status.options.ReplyMarkup != keyboard || len(status.options.Entities) != 1 {
		t.Fatal("artwork, caption and buttons were not edited together")
	}
	if err := editIMDbCard(context.Background(), status, pages[0], nil, keyboard); err != nil {
		t.Fatal(err)
	}
	if status.calls != 2 || status.options.Media != nil {
		t.Fatal("caption navigation should retain the existing media")
	}
	status.err = errors.New("edit rejected")
	if err := editIMDbCard(context.Background(), status, pages[0], artwork, keyboard); !errors.Is(err, status.err) {
		t.Fatal("edit error swallowed")
	}
}

func imdbTestButtons(kb *tg.ReplyInlineMarkup) (labels []string, callbacks []string) {
	for _, row := range kb.Rows {
		for _, button := range row.Buttons {
			labels = append(labels, button.Text)
			switch b := button.Type.(type) {
			case *tg.InlineButtonTypeCallback:
				callbacks = append(callbacks, string(b.Data))
			}
		}
	}
	return labels, callbacks
}

func TestIMDbRecommendationsExpandOnlyOnClick(t *testing.T) {
	year := 2003
	page := imdbSearchPage{owner: 123, titleID: "tt0133093", keyboard: tg.NewKeyboard().Build(),
		details: []imdbCaptionPage{{text: "The Matrix"}}, recommendations: []scraper.Recommendation{
			{IMDbID: "tt0234215", Title: "The Matrix Reloaded", Year: &year},
			{IMDbID: "tt0242653", Title: "The Matrix Revolutions"},
		}}
	labels, callbacks := imdbTestButtons(imdbDetailsKeyboard(page, 0))
	if !reflect.DeepEqual(labels, []string{"IMDb", "More like this", "Go back"}) ||
		!reflect.DeepEqual(callbacks, []string{"imdb:123:similar", "imdb:123:back"}) {
		t.Fatalf("initial card exposed recommendations: %v %v", labels, callbacks)
	}
	page.expanded = true
	labels, callbacks = imdbTestButtons(imdbDetailsKeyboard(page, 0))
	if !reflect.DeepEqual(labels, []string{"The Matrix Reloaded (2003)", "The Matrix Revolutions", "IMDb", "Go back"}) ||
		!reflect.DeepEqual(callbacks, []string{"imdb:123:tt0234215", "imdb:123:tt0242653", "imdb:123:collapse"}) {
		t.Fatalf("expanded recommendations did not navigate within the bot: %v %v", labels, callbacks)
	}
	page.expanded = false
	labels, _ = imdbTestButtons(imdbDetailsKeyboard(page, 0))
	if !reflect.DeepEqual(labels, []string{"IMDb", "More like this", "Go back"}) {
		t.Fatalf("back failed to collapse recommendations: %v", labels)
	}
}

func TestIMDbRecommendationHistoryRestoresPreviousView(t *testing.T) {
	searchKeyboard := tg.NewKeyboard().Build()
	page := imdbSearchPage{owner: 123, text: "search results", keyboard: searchKeyboard}
	var err error
	page, err = imdbNavigateTitle(page, "tt0133093")
	if err != nil {
		t.Fatal(err)
	}
	page.detailIndex, page.expanded = 1, true
	sequel, err := imdbNavigateTitle(page, "tt0234215")
	if err != nil || sequel.expanded || sequel.detailIndex != 0 || len(sequel.history) != 1 {
		t.Fatalf("new recommendation did not open collapsed: %+v %v", sequel, err)
	}
	if page.titleID != "tt0133093" || len(page.history) != 0 || !page.expanded {
		t.Fatal("staging a selection mutated the saved card before a successful edit")
	}
	sequel.expanded = true
	third, err := imdbNavigateTitle(sequel, "tt0242653")
	if err != nil {
		t.Fatal(err)
	}
	back, err := imdbNavigateTitle(third, "prevtitle")
	if err != nil || back.titleID != sequel.titleID || !back.expanded || len(back.history) != 1 {
		t.Fatalf("back did not restore second title's recommendation view: %+v %v", back, err)
	}
	back, err = imdbNavigateTitle(back, "prevtitle")
	if err != nil || back.titleID != page.titleID || !back.expanded || back.detailIndex != 1 || len(back.history) != 0 {
		t.Fatalf("back did not restore first title's caption page: %+v %v", back, err)
	}
	results := imdbResultsPage(back)
	if results.titleID != "" || results.expanded || len(results.history) != 0 || results.text != page.text || results.keyboard != searchKeyboard {
		t.Fatal("return to search lost results or retained title history")
	}
	if _, err := imdbNavigateTitle(results, "prevtitle"); err == nil {
		t.Fatal("accepted back without previous title")
	}
	if _, err := imdbNavigateTitle(results, "bad-id"); err == nil {
		t.Fatal("accepted invalid title")
	}
}

func TestIMDbRecommendationsFilterAndLimit(t *testing.T) {
	recs := []scraper.Recommendation{
		{IMDbID: "bad", Title: "Invalid"}, {IMDbID: "tt0133093", Title: "Current title"},
		{IMDbID: "tt0234215", Title: "Reloaded"}, {IMDbID: "tt0234215", Title: "Duplicate"},
		{IMDbID: "tt0242653", Title: " "},
	}
	for _, id := range []string{"tt0000001", "tt0000002", "tt0000003", "tt0000004", "tt0000005", "tt0000006"} {
		recs = append(recs, scraper.Recommendation{IMDbID: id, Title: "Another movie"})
	}
	filtered := imdbRecommendations("tt0133093", recs)
	if len(filtered) != 6 || filtered[0].IMDbID != "tt0234215" || filtered[5].IMDbID != "tt0000005" {
		t.Fatalf("invalid, duplicate, or excessive recommendations: %+v", filtered)
	}
	page := imdbSearchPage{owner: 9223372036854775807, titleID: "tt0133093", expanded: true, recommendations: filtered}
	_, callbacks := imdbTestButtons(imdbDetailsKeyboard(page, 0))
	for _, data := range callbacks {
		if len(data) > 64 {
			t.Fatalf("callback exceeds Telegram limit: %q", data)
		}
	}
}
