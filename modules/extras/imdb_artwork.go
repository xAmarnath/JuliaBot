package extras

import (
	"context"
	"fmt"
	"io"
	"main/internal/imdb/scraper"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"

	tg "github.com/xAmarnath/gogram/telegram"
)

func loadIMDbArtwork(ctx context.Context, c *scraper.Scraper, d *scraper.Details) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var data []byte
	var err error
	if d.Poster != nil {
		data, err = downloadIMDbArtwork(ctx, *d.Poster)
	}
	if len(data) == 0 {
		images, imageErr := c.GetImages(ctx, d.IMDbID, 4)
		if imageErr != nil {
			return nil, imageErr
		}
		for _, candidate := range imdbImageCandidates(images) {
			data, err = downloadIMDbArtwork(ctx, candidate)
			if err == nil {
				break
			}
		}
	}
	if len(data) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("no poster or still available")
	}
	return data, nil
}

func imdbImageCandidates(images *scraper.ImagesResult) []string {
	if images == nil {
		return nil
	}
	var urls []string
	if images.PrimaryImage != nil {
		urls = append(urls, images.PrimaryImage.URL)
	}
	for _, image := range images.Images {
		urls = append(urls, image.URL)
	}
	return urls
}

type imdbCaptionPage struct {
	text     string
	entities []tg.MessageEntity
}

// Telegram measures caption and entity lengths in UTF-16 code units. Split
// the formatted details without losing text, links, or supplementary characters.
func imdbCaptionPages(formatted string) ([]imdbCaptionPage, error) {
	text, tags, err := tg.ParseHTMLToTags(formatted)
	if err != nil {
		return nil, err
	}
	units := utf16.Encode([]rune(text))
	var pages []imdbCaptionPage
	for start := 0; start < len(units); {
		end := min(start+1024, len(units))
		if end < len(units) {
			if units[end-1] >= 0xd800 && units[end-1] <= 0xdbff {
				end--
			}
			for i := end - 1; i > start+512; i-- {
				if units[i] == '\n' {
					end = i + 1
					break
				}
			}
		}
		page := imdbCaptionPage{text: string(utf16.Decode(units[start:end])), entities: []tg.MessageEntity{}}
		for _, tag := range tags {
			lo, hi := max(start, int(tag.Offset)), min(end, int(tag.Offset+tag.Length))
			if lo >= hi {
				continue
			}
			offset, length := int32(lo-start), int32(hi-lo)
			switch tag.Type {
			case "b", "strong":
				page.entities = append(page.entities, &tg.MessageEntityBold{Offset: offset, Length: length})
			case "a":
				page.entities = append(page.entities, &tg.MessageEntityTextURL{Offset: offset, Length: length, URL: tag.Attrs["href"]})
			}
		}
		pages = append(pages, page)
		start = end
	}
	if len(pages) == 0 {
		pages = []imdbCaptionPage{{text: "IMDb", entities: []tg.MessageEntity{}}}
	}
	return pages, nil
}

type imdbMessageEditor interface {
	Edit(any, ...*tg.SendOptions) (*tg.NewMessage, error)
}

func editIMDbCard(ctx context.Context, status imdbMessageEditor, page imdbCaptionPage, artwork []byte, keyboard *tg.ReplyInlineMarkup) error {
	opt := &tg.SendOptions{ParseMode: "none", Entities: page.entities, ReplyMarkup: keyboard}
	if len(artwork) > 0 {
		opt.Media = artwork
		opt.FileName = "imdb-artwork.jpg"
		opt.Upload = &tg.UploadOptions{Ctx: ctx}
	}
	_, err := status.Edit(page.text, opt)
	return err
}

func imdbArtworkURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return ""
	}
	switch strings.ToLower(u.Hostname()) {
	case "m.media-amazon.com", "ia.media-imdb.com", "images-na.ssl-images-amazon.com":
	default:
		return ""
	}
	if i := strings.Index(u.Path, "._V1_"); i >= 0 {
		u.Path = u.Path[:i] + "._V1_QL85_UX1000_.jpg"
	}
	return u.String()
}

func downloadIMDbArtwork(ctx context.Context, raw string) ([]byte, error) {
	link := imdbArtworkURL(raw)
	if link == "" {
		return nil, fmt.Errorf("invalid IMDb image URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("artwork HTTP %d", resp.StatusCode)
	}
	const maxImage = 10 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxImage+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxImage || len(data) == 0 || !strings.HasPrefix(http.DetectContentType(data), "image/") {
		return nil, fmt.Errorf("artwork is not a supported image under 10 MiB")
	}
	return data, nil
}
