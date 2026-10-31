package scraper

import (
	"context"
	"regexp"
	"sort"
	"strings"
)

type PlaybackHeaders struct {
	Referer   string `json:"Referer"`
	UserAgent string `json:"User-Agent"`
}

type TrailerResult struct {
	VideoID         string          `json:"video_id"`
	StreamURL       string          `json:"stream_url"`
	MimeType        string          `json:"mime_type"`
	Definition      *string         `json:"definition"`
	Fallback        bool            `json:"fallback,omitempty"`
	PlaybackHeaders PlaybackHeaders `json:"playback_headers"`
}

var videoIDInGalleryRe = regexp.MustCompile(`href="[^"]*?/video/vi(\d+)`)

var defOrder = map[string]int{"1080p": 0, "720p": 1, "480p": 2, "360p": 3}

func (s *Scraper) findVideoIDViaTitlePage(ctx context.Context, imdbID string) string {
	url := baseURL + "/title/" + imdbID + "/"
	body, err := s.FetchHTML(ctx, url)
	if err != nil || body == "" {
		return ""
	}
	nd := extractNextData(body)
	if nd == nil {
		return ""
	}
	af := walkMap(nd, "props", "pageProps", "aboveTheFoldData")
	edges := walkList(af, "primaryVideos", "edges")
	var trailerID, firstID string
	for _, e := range edges {
		node := walkMap(e, "node")
		if node == nil {
			continue
		}
		vid := walkString(node, "id")
		if vid == "" {
			continue
		}
		if firstID == "" {
			firstID = vid
		}
		name := strings.ToLower(walkString(node, "name", "value"))
		ctype := strings.ToLower(walkString(node, "contentType", "id"))
		if strings.Contains(name, "trailer") || ctype == "trailer" {
			trailerID = vid
			break
		}
	}
	if trailerID != "" {
		return trailerID
	}
	return firstID
}

func extractVideoIDFromGallery(body string) string {
	matches := videoIDInGalleryRe.FindAllStringSubmatchIndex(body, -1)
	var trailerID, clipID, firstID string
	for _, idx := range matches {
		id := "vi" + body[idx[2]:idx[3]]
		start := idx[1]
		end := start + 400
		if end > len(body) {
			end = len(body)
		}
		ctx := strings.ToLower(body[start:end])
		if firstID == "" {
			firstID = id
		}
		if trailerID == "" && strings.Contains(ctx, "trailer") {
			trailerID = id
		} else if clipID == "" && strings.Contains(ctx, "clip") {
			clipID = id
		}
	}
	if trailerID != "" {
		return trailerID
	}
	if clipID != "" {
		return clipID
	}
	return firstID
}

func (s *Scraper) fallbackStream(videoID string) *TrailerResult {
	def := "720p"
	return &TrailerResult{
		VideoID:    videoID,
		StreamURL:  "https://imdb-video.media-imdb.com/mc/" + videoID + "/" + videoID + "_720p.mp4",
		MimeType:   "MP4",
		Definition: &def,
		Fallback:   true,
		PlaybackHeaders: PlaybackHeaders{
			Referer:   "https://www.imdb.com/",
			UserAgent: imdbUserAgent,
		},
	}
}

func (s *Scraper) getStreamURL(ctx context.Context, videoID string) *TrailerResult {
	url := baseURL + "/video/" + videoID + "/"
	body, err := s.FetchHTML(ctx, url)
	if err != nil || body == "" {
		return s.fallbackStream(videoID)
	}
	nd := extractNextData(body)
	if nd == nil {
		return s.fallbackStream(videoID)
	}
	urls := walkList(nd, "props", "pageProps", "videoPlaybackData", "video", "playbackURLs")
	if len(urls) == 0 {
		return s.fallbackStream(videoID)
	}

	type entry struct {
		u        map[string]any
		mime     string
		def      string
		defOrder int
	}
	var mp4s, hls, rest []entry
	for _, u := range urls {
		m := walkMap(u)
		mime := strings.ToUpper(walkString(u, "videoMimeType"))
		def := walkString(u, "videoDefinition")
		e := entry{u: m, mime: mime, def: def, defOrder: defOrder[def]}
		if _, ok := defOrder[def]; !ok {
			e.defOrder = 99
		}
		switch mime {
		case "MP4":
			mp4s = append(mp4s, e)
		case "M3U8":
			hls = append(hls, e)
		default:
			rest = append(rest, e)
		}
	}
	var chosen entry
	if len(mp4s) > 0 {
		sort.SliceStable(mp4s, func(i, j int) bool { return mp4s[i].defOrder < mp4s[j].defOrder })
		chosen = mp4s[0]
	} else if len(hls) > 0 {
		chosen = hls[0]
	} else if len(rest) > 0 {
		chosen = rest[0]
	} else {
		return s.fallbackStream(videoID)
	}

	streamURL := walkString(chosen.u, "url")
	if streamURL == "" {
		return s.fallbackStream(videoID)
	}
	var defPtr *string
	if chosen.def != "" {
		d := chosen.def
		defPtr = &d
	}
	mime := chosen.mime
	if mime == "" {
		mime = "MP4"
	}
	return &TrailerResult{
		VideoID:    videoID,
		StreamURL:  streamURL,
		MimeType:   mime,
		Definition: defPtr,
		PlaybackHeaders: PlaybackHeaders{
			Referer:   "https://www.imdb.com/",
			UserAgent: imdbUserAgent,
		},
	}
}

func (s *Scraper) GetTrailerURL(ctx context.Context, imdbID string) (*TrailerResult, error) {
	vid := s.findVideoIDViaTitlePage(ctx, imdbID)
	if vid == "" {
		body, err := s.FetchHTML(ctx, baseURL+"/title/"+imdbID+"/videogallery/?sort=date,desc")
		if err != nil {
			return nil, err
		}
		if body != "" {
			vid = extractVideoIDFromGallery(body)
		}
	}
	if vid == "" {
		return nil, nil
	}
	return s.getStreamURL(ctx, vid), nil
}
