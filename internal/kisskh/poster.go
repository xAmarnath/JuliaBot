package kisskh

import (
	"bytes"
	"context"
	"fmt"
	_ "golang.org/x/image/webp"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// PosterThumbnail downloads a bounded image and produces a Telegram-compatible JPEG thumbnail.
func (c *Client) PosterThumbnail(ctx context.Context, url, path string) error {
	if url == "" {
		return fmt.Errorf("no poster available")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return e
	}
	req.Header.Set("User-Agent", UserAgent)
	response, e := c.HTTP.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("poster HTTP %d", response.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 5*1024*1024+1))
	if e != nil {
		return e
	}
	if len(raw) > 5*1024*1024 {
		return fmt.Errorf("poster too large")
	}
	dimensions, _, e := image.DecodeConfig(bytes.NewReader(raw))
	if e != nil {
		return e
	}
	if dimensions.Width <= 0 || dimensions.Height <= 0 || int64(dimensions.Width)*int64(dimensions.Height) > 20000000 {
		return fmt.Errorf("poster dimensions invalid")
	}
	input := filepath.Join(filepath.Dir(path), "poster-source")
	if e = os.WriteFile(input, raw, 0600); e != nil {
		return e
	}
	defer os.Remove(input)
	if e = run(ctx, "ffmpeg", "-nostdin", "-v", "error", "-y", "-i", input, "-frames:v", "1", "-vf", "scale=320:320:force_original_aspect_ratio=decrease", "-q:v", "5", path); e != nil {
		return e
	}
	stat, e := os.Stat(path)
	if e != nil {
		return e
	}
	if stat.Size() > 200*1024 {
		return fmt.Errorf("poster thumbnail too large")
	}
	return nil
}
