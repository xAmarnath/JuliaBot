package extras

import (
	"os"
	"strings"
	"testing"
)

func TestInstagramDownloadLinksKeepIconsWithTheirLinks(t *testing.T) {
	raw := `<div><a href="https://cdn.test/thumb.jpg"><img src="x"></a>
<a class="button" href="https://cdn.test/reel.mp4?a=1&amp;b=2"><i class="icon icon-dlvideo"></i>Video</a>
<a href="https://cdn.test/next.jpg"><i class="icon icon-dlimage"></i>Image</a></div>`
	for _, input := range []string{raw, strings.ReplaceAll(raw, `"`, `\"`)} {
		media := parseInstagramDownloadLinks(input)
		if len(media.Videos) != 1 || media.Videos[0] != "https://cdn.test/reel.mp4?a=1&b=2" || len(media.Images) != 1 || media.Images[0] != "https://cdn.test/next.jpg" {
			t.Fatalf("wrong media links: %#v", media)
		}
	}
	media := parseInstagramDownloadLinks(`<div class="download-items"><div class="download-items__thumb"><i class="icon icon-dlvideo"></i></div>
<a href="https://cdn.test/thumbnail.jpg" title="Download Thumbnail"><i class="icon icon-download"></i>Download Thumbnail</a>
<a href="https://cdn.test/real.mp4" title="Download Video"><i class="icon icon-download"></i>Download Video</a></div>`)
	if len(media.Videos) != 1 || media.Videos[0] != "https://cdn.test/real.mp4" || len(media.Images) != 0 {
		t.Fatalf("thumbnail selected as reel: %#v", media)
	}
}

func TestMalformedProviderDecoder(t *testing.T) {
	for _, offset := range []int{-1, 0, 1, 3, 100} {
		if decodeX("test", 0, "abc", 0, offset, 0) != "" {
			t.Fatal(offset)
		}
	}
}

// Read-only provider check: downloads media locally without sending Telegram messages.
func TestInstagramReportedReelsLive(t *testing.T) {
	if os.Getenv("JB_SOCIAL_TEST") != "1" {
		t.Skip("JB_SOCIAL_TEST not set")
	}
	for _, id := range []string{"DeTqasfzReW", "DeSVeZ5vA4j"} {
		t.Run(id, func(t *testing.T) {
			resp, err := FetchInstagramMedia("https://www.instagram.com/reel/" + id)
			if err != nil || resp == nil {
				t.Fatalf("resolve reel: %v", err)
			}
			if resp.Error != "" || len(resp.Videos) == 0 {
				t.Fatalf("reel unavailable: %s", resp.Error)
			}
			data, err := downloadURL(resp.Videos[0])
			if err != nil {
				t.Fatal(err)
			}
			mime, _ := detectMimeAndExt(data)
			if !strings.HasPrefix(mime, "video/") {
				t.Fatalf("expected video, got %s", mime)
			}
			t.Logf("resolved %d video(s), downloaded %d bytes (%s)", len(resp.Videos), len(data), mime)
		})
	}
}
